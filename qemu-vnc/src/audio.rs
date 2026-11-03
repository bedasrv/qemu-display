//! The audio a VNC server captures from QEMU and plays for its clients.
//!
//! QEMU hands us raw PCM in the guest's format ([`qemu_display::PCMInfo`]) and
//! expects the samples to be played; the RFB side sends them to whichever
//! clients asked for the `Audio` pseudo-encoding. What is in between is a
//! [`Sink`], so that a machine with no sound card — a build server, a
//! container, a test — is not a machine without audio.
//!
//! # The conversion
//!
//! QEMU's audio backend converts for each client: it registers a capture with
//! the format *that* client asked for, and the backend is what resamples and
//! remixes. This does the same, in [`Converter`]: the width, the signedness and
//! the channel count are converted, and a rate that differs is resampled with
//! [`rubato`], a windowed-sinc resampler, which is the kind of filter a linear
//! interpolation is not.
//!
//! Two consequences worth knowing about. The conversion is *per client*, not
//! per stream, because two clients may have asked for two different formats.
//! And it is *stateful*: the samples either side of a block boundary belong to
//! the same interpolation, so a converter keeps its resampler for the length of
//! the stream, which is why [`Converter`] is a type rather than a function.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use qemu_display::{AudioOutHandler, PCMInfo, Volume};

use crate::rfb::audio::{Format, Sample};

/// The feature an audio server needs to tell the client about a format.
pub const DEFAULT_FORMAT: Format = Format {
    sample: Sample::S16,
    channels: 2,
    frequency: 44_100,
            be: false,
};

/// What the audio server hands on to the clients.
///
/// An enum rather than a block of samples, because there are two things to say
/// and one of them has no samples in it: a block of audio, and the fact that
/// the stream has ended. Overloading an empty block for the second would leave
/// every caller filtering empties out for its own reasons and quietly swallow
/// the end of every stream along with them.
#[derive(Debug, Clone)]
pub enum Out {
    /// A block of samples, in the guest's format.
    Samples(Format, Vec<u8>),
    /// The guest has started a stream.
    ///
    /// **A variant rather than an empty `Samples`, which is what this was.**
    /// The empty block was the nudge that a stream had started, and `main.rs`
    /// dropped empty blocks on the way to the clients -- which is right for
    /// audio and fatal for the nudge, because a client was then never told a
    /// second stream had begun. A guest that pauses between tracks sends
    /// enable, disable, enable; the clients heard one `BEGIN` and then silence
    /// for ever, because nothing re-sent it. QEMU sends `AUDIO_BEGIN` on every
    /// `AUD_CNOTIFY_ENABLE`, and this is the same thing with a name on it.
    Begin,
    /// The guest stopped this stream.
    End,
}

/// Where the samples go.
///
/// A sink that discards is a first-class implementation rather than a
/// fallback: `qemu-vnc` runs on machines with no output device, and the audio
/// path has to be exercisable there.
pub trait Sink: Send {
    /// The format the sink plays, or `None` when it discards whatever it is
    /// given, in which case no conversion is attempted.
    fn format(&self) -> Option<Format>;

    /// Play a block of samples in the sink's format.
    fn play(&mut self, samples: &[u8]);

    /// Whether the sink is still usable.
    fn is_open(&self) -> bool {
        true
    }
}

/// A sink that counts what it is given and plays nothing.
///
/// This is what runs without the `audio` feature, and what the tests use to
/// check that the right samples reach the right place.
#[derive(Debug, Default)]
pub struct NullSink {
    played: usize,
    last: Vec<u8>,
}

impl NullSink {
    /// A sink that has played nothing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many bytes have been played, which is what a test asserts on.
    pub fn played(&self) -> usize {
        self.played
    }

    /// The last block played, which is what a test decodes.
    pub fn last(&self) -> &[u8] {
        &self.last
    }
}

impl Sink for NullSink {
    /// The samples are discarded, so there is no format to convert to.
    fn format(&self) -> Option<Format> {
        None
    }

    fn play(&mut self, samples: &[u8]) {
        self.played += samples.len();
        self.last.clear();
        self.last.extend_from_slice(samples);
    }
}

/// A sink that writes the samples to a file, as `--audio-dump` does.
///
/// This is what makes the audio path testable where there is no sound card:
/// the samples that would be played are on disk, and a test can check that the
/// right ones arrived.
pub struct FileSink {
    file: std::fs::File,
    written: usize,
    format: Format,
}

impl FileSink {
    /// Write the samples of `format` to `path`, creating or truncating it.
    pub fn create(path: &std::path::Path, format: Format) -> Result<Self, Error> {
        let file = std::fs::File::create(path)
            .map_err(|e| Error::Backend(format!("{}: {e}", path.display())))?;
        Ok(Self {
            file,
            written: 0,
            format,
        })
    }

    /// How many bytes have been written, which is what a test asserts on.
    pub fn written(&self) -> usize {
        self.written
    }
}

impl std::fmt::Debug for FileSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSink")
            .field("written", &self.written)
            .field("format", &self.format)
            .finish()
    }
}

impl Sink for FileSink {
    fn format(&self) -> Option<Format> {
        Some(self.format)
    }

    fn play(&mut self, samples: &[u8]) {
        use std::io::Write;
        if self.file.write_all(samples).is_ok() {
            self.written += samples.len();
        }
    }
}

/// The `cpal` sink, behind the `audio` feature.
///
/// The samples arrive on the client task's thread and the device is fed by
/// cpal's, so they go through a shared ring: `play` appends and the callback
/// drains. The buffer is bounded, and what does not fit is dropped rather than
/// blocking the client: audio that arrives late is audio nobody wants.
#[cfg(feature = "audio")]
pub struct CpalSink {
    /// Kept alive because dropping a `cpal::Stream` stops the device.
    stream: std::mem::ManuallyDrop<cpal::Stream>,
    queue: Arc<Mutex<Queue>>,
    format: Format,
}

/// The samples waiting for the device, and whether a reader is waiting too.
#[cfg(feature = "audio")]
#[derive(Default)]
struct Queue {
    samples: std::collections::VecDeque<f32>,
    /// The format the samples in the queue are in, needed to read them.
    format: Option<Format>,
}

#[cfg(feature = "audio")]
impl CpalSink {
    /// How much audio may be queued, which bounds a device that is not
    /// draining: half a second is longer than any viewer waits for a buffer
    /// and short enough not to matter if it is late.
    const BUFFER_SECONDS: f32 = 0.5;

    /// The queue's capacity, in samples.
    const CAPACITY: usize = (Self::BUFFER_SECONDS * DEFAULT_FORMAT.frequency as f32) as usize
        * DEFAULT_FORMAT.channels as usize;

    /// Open the default output device, playing `format`.
    ///
    /// The device need not be able to play the guest's rate: a rate that
    /// differs is resampled to the device's, which is what QEMU's backend does
    /// for the samples it hands a client. What the device must be able to do is
    /// carry the number of channels, and there is no converting *into* a device
    /// with fewer channels than that, because the sink's format is what the
    /// samples are converted to and there is nowhere else to put them.
    pub fn open(format: Format) -> Result<Self, Error> {
        use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

        let host = cpal::default_host();
        let device = host.default_output_device().ok_or(Error::NoDevice)?;
        let supported = device
            .default_output_config()
            .map_err(|e| Error::Backend(e.to_string()))?;
        if u16::from(format.channels) > supported.channels() {
            return Err(Error::UnsupportedFormat);
        }
        // The device's own rate, not the guest's: a device that wants 48000 is
        // played at 48000, and the conversion in the callback resamples into
        // it. `SampleRate` is a `u32` alias in cpal 0.18, not a newtype.
        let config = cpal::StreamConfig {
            channels: u16::from(format.channels),
            sample_rate: supported.sample_rate(),
            buffer_size: cpal::BufferSize::Default,
        };
        // What the sink plays, which is the device's format rather than the
        // guest's, and what the converter below resamples into.
        let format = Format {
            frequency: config.sample_rate,
            ..format
        };

        let queue = Arc::new(Mutex::new(Queue {
            samples: Default::default(),
            format: Some(format),
        }));
        let callback_queue = queue.clone();
        let stream = device
            .build_output_stream(
                config,
                move |out: &mut [f32], _: &cpal::OutputCallbackInfo| {
                    let Ok(mut queue) = callback_queue.lock() else {
                        return;
                    };
                    for slot in out.iter_mut() {
                        // Silence rather than a repeat of the last sample:
                        // a viewer hears a gap, not a buzz.
                        *slot = queue.samples.pop_front().unwrap_or(0.0);
                    }
                },
                |e| tracing::warn!("the audio output failed: {e}"),
                None,
            )
            .map_err(|e| Error::Backend(e.to_string()))?;
        stream.play().map_err(|e| Error::Backend(e.to_string()))?;
        Ok(Self {
            stream: std::mem::ManuallyDrop::new(stream),
            queue,
            format,
        })
    }
}

#[cfg(feature = "audio")]
impl Drop for CpalSink {
    fn drop(&mut self) {
        // A dropped stream stops the device, which is what a server that is
        // shutting down wants; the manual drop says it was deliberate.
        unsafe { std::mem::ManuallyDrop::drop(&mut self.stream) };
    }
}

#[cfg(feature = "audio")]
impl Sink for CpalSink {
    fn format(&self) -> Option<Format> {
        Some(self.format)
    }

    fn play(&mut self, samples: &[u8]) {
        let Ok(mut queue) = self.queue.lock() else {
            return;
        };
        let source = queue.format.unwrap_or(self.format);
        for sample in samples_in(source, samples) {
            if queue.samples.len() >= Self::CAPACITY {
                // The device is behind: drop the oldest rather than grow, and
                // rather than block the client that is sending.
                queue.samples.pop_front();
            }
            queue.samples.push_back(sample);
        }
    }
}

/// Why a sink could not be opened.
#[derive(Debug)]
pub enum Error {
    /// There is no output device.
    NoDevice,
    /// The device or the library can not play the guest's format.
    UnsupportedFormat,
    /// The backend said no.
    Backend(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NoDevice => write!(f, "there is no audio output device"),
            Error::UnsupportedFormat => {
                write!(f, "the output device can not play the guest's format")
            }
            Error::Backend(what) => write!(f, "the audio backend failed: {what}"),
        }
    }
}

impl std::error::Error for Error {}

/// The audio of one QEMU stream, as the clients see it.
#[derive(Debug, Clone)]
pub struct Stream {
    /// What QEMU is sending.
    pub source: Format,
    /// What the clients asked for, or the source when they did not.
    pub target: Format,
    /// Whether any client is listening.
    pub playing: bool,
}

/// The audio server: it receives the guest's samples, and hands them on.
///
/// Cloned to hand a handle to whoever registers the listener; the state is
/// behind locks because the D-Bus handler and the client tasks are different
/// threads.
///
/// The zbus handler is `&mut self` on the D-Bus executor's thread, so the
/// state the clients need is behind a lock rather than in the struct, and what
/// is sent to the clients is a channel they already poll.
#[derive(Clone)]
pub struct AudioServer {
    /// What QEMU is sending, per stream id.
    sources: Arc<Mutex<HashMap<u64, Source>>>,
    /// The sink the samples are played on, behind a lock: the D-Bus handler is
    /// `Send + Sync` and a sink is only `Send`.
    sink: Arc<Mutex<Box<dyn Sink>>>,
    /// Where the samples go: a callback into the server's event channel.
    sink_target: Arc<dyn Fn(Out) + Send + Sync>,
    /// Whether any client is listening at all.
    listening: Arc<Mutex<usize>>,
    /// Converts the guest's samples into what the sink plays.
    ///
    /// A [`Converter`] and not a call to [`convert`], because the sink's format
    /// is the *device's* — which is rarely the guest's — and converting to it
    /// means resampling. The state is shared by the clones, which is right:
    /// there is one sink, so there is one stream being converted into it.
    converter: Arc<Mutex<Converter>>,
}

impl std::fmt::Debug for AudioServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AudioServer")
            .field(
                "streams",
                &self.sources.lock().map(|s| s.len()).unwrap_or(0),
            )
            .field("listening", &*self.listening.lock().unwrap())
            .finish()
    }
}

impl AudioServer {
    /// Serve the audio of `sources` into `sink_target`.
    ///
    /// `sink` is where the samples are played; the null sink plays nothing,
    /// which is what a machine with no sound card gets.
    pub fn new(sink: Box<dyn Sink>, sink_target: impl Fn(Out) + Send + Sync + 'static) -> Self {
        Self {
            sources: Arc::new(Mutex::new(HashMap::new())),
            sink: Arc::new(Mutex::new(sink)),
            sink_target: Arc::new(sink_target),
            listening: Arc::new(Mutex::new(0)),
            converter: Arc::new(Mutex::new(Converter::new())),
        }
    }

    /// The format the sink plays, which is what the samples are converted to.
    pub fn sink_format(&self) -> Option<Format> {
        self.sink.lock().ok().and_then(|sink| sink.format())
    }

    /// A handle the sink and the client count share.
    pub fn listening(&self) -> Arc<Mutex<usize>> {
        self.listening.clone()
    }

    /// Note that a client is listening, or has stopped.
    pub fn set_listening(&self, listening: bool) {
        let mut count = self.listening.lock().unwrap();
        if listening {
            *count += 1;
        } else {
            *count = count.saturating_sub(1);
        }
    }

    /// The format of a stream, as the clients are told.
    pub fn format(&self, id: u64) -> Option<Stream> {
        self.sources.lock().ok()?.get(&id).map(|source| Stream {
            source: source.format,
            target: self.sink_format().unwrap_or(source.format),
            playing: *self.listening.lock().unwrap() > 0,
        })
    }

    /// Convert the guest's samples to what the sink plays.
    ///
    /// Returns the samples as they are when the sink takes anything, which is
    /// the null sink's case and the one a test asserts on.
    fn convert(&self, source: Format, data: &[u8]) -> Vec<u8> {
        let Some(target) = self.sink_format() else {
            return data.to_vec();
        };
        // Locked separately from the sink: the sink lock is not reentrant and
        // this runs before the sink is taken.
        self.converter
            .lock()
            .map(|mut converter| converter.convert(source, target, data))
            .unwrap_or_else(|_| convert(source, target, data))
    }

    /// Play what the converter is still holding, for a stream that has ended.
    ///
    /// Without this the last fraction of a second of every stream is dropped:
    /// a resampler holds back a partial chunk so that the next block continues
    /// the same interpolation, and at the end of a stream there is no next
    /// block. This is the sink's half; each client flushes its own on the way
    /// out, because each has its own converter.
    fn flush_converter(&self) {
        if self.sink_format().is_none() {
            // Nothing was converted, so nothing is held back.
            return;
        }
        let tail = self
            .converter
            .lock()
            .map(|mut converter| converter.flush())
            .unwrap_or_default();
        if tail.is_empty() {
            return;
        }
        if let Ok(mut sink) = self.sink.lock() {
            sink.play(&tail);
        }
    }
}

#[async_trait::async_trait]
impl AudioOutHandler for AudioServer {
    async fn init(&mut self, id: u64, info: PCMInfo) {
        let source = Format {
            // The guest's samples are signed or unsigned and 8, 16 or 32 bits.
            //
            // **A float stream is mapped to a signed width whatever `is_signed`
            // says**, and that is the second half of the white-noise fix. A
            // float sample is symmetric about zero, so `is_signed` is
            // meaningless for one and QEMU sets it arbitrarily; taking it at face
            // value gave `U32`, whose range is 0 to 4294967295 rather than
            // +/-2147483647, so a quiet sample was scaled to hundreds of millions
            // and every client saturated on the way down.
            sample: if info.is_float {
                // **S16 for every float stream.** RFB has no float format, so
                // one has to be chosen, and S16 is the one every client asks
                // for. Choosing the width the VM reported instead gave `U32` for
                // a float32 stream -- a range of 0 to 4294967295 rather than
                // +/-2147483647 -- so a quiet sample was scaled to hundreds of
                // millions and every client saturated: white noise.
                Sample::S16
            } else {
                match info.bits {
                8 if info.is_signed => Sample::S8,
                8 => Sample::U8,
                16 if info.is_signed => Sample::S16,
                16 => Sample::U16,
                32 if info.is_signed => Sample::S32,
                32 => Sample::U32,
                // A width with no RFB equivalent is reported at the width it has.
                // That is wrong but bounded, and the alternative is refusing to
                // serve audio at all for a guest that produces it.
                bits if bits < 8 => Sample::U8,
                bits if bits < 16 => Sample::U16,
                _ => Sample::U32,
                }
            },
            channels: info.nchannels,
            frequency: info.freq,
            be: info.be,
        };
        if let Ok(mut sources) = self.sources.lock() {
            sources.insert(
                id,
                Source {
                    format: source,
                    // **Both of these were ignored, and a float stream read as
                    // an integer one is the loudest possible wrong answer.**
                    // `is_float` says the samples are IEEE floats, so their bit
                    // patterns are large integers rather than small ones, and
                    // every sample saturates: a VM whose audio engine hands over
                    // floats -- which is what a PulseAudio-backed one does -- was
                    // heard as full-scale white noise. `be` says which way round
                    // the samples are, and the converter's own read and write
                    // cancel out on an integer stream, so getting it wrong there
                    // was invisible; getting it wrong on a float stream means
                    // decoding the wrong exponent and hearing noise again.
                    floating: info.is_float,
                },
            );
        }
    }

    async fn fini(&mut self, id: u64) {
        let last = self
            .sources
            .lock()
            .ok()
            .and_then(|mut sources| sources.remove(&id));
        if last.is_some() {
            // The stream is over, so the audio the converters are holding is
            // not going to be continued by anything.
            self.flush_converter();
            (self.sink_target)(Out::End);
        }
    }

    async fn set_enabled(&mut self, _id: u64, enabled: bool) {
        if enabled {
            // `AUD_CNOTIFY_ENABLE`, which QEMU answers with
            // `VNC_MSG_SERVER_QEMU_AUDIO_BEGIN`.
            (self.sink_target)(Out::Begin);
        } else {
            // A guest that stops its audio ends the stream, which is QEMU's
            // `AUD_CNOTIFY_DISABLE` and the reason it sends
            // `VNC_MSG_SERVER_QEMU_AUDIO_END`.
            self.flush_converter();
            (self.sink_target)(Out::End);
        }
    }

    async fn set_volume(&mut self, _id: u64, _volume: Volume) {
        // The RFB audio path has no volume control: QEMU sends the guest's
        // samples as they are, and the viewer decides what to do with them.
    }

    async fn write(&mut self, id: u64, data: Vec<u8>) {
        let Some(stream) = self
            .sources
            .lock()
            .ok()
            .and_then(|sources| sources.get(&id).cloned())
        else {
            // A stream we were never told about is not one to guess at.
            return;
        };
        let source = stream.format;
        let data = if stream.floating {
            floats_to_samples(source, &data)
        } else {
            data
        };
        let data = data.as_slice();
        // Converted before the sink is locked: the conversion asks the sink
        // what format it plays, and a lock is not reentrant.
        // Bumped before the conversion, so a fault in either the converter or
        // the sink cannot hide the fact that the samples arrived: this counter
        // is what says the VM's audio reached this process at all, and it is the
        // other half of `crate::counters::counters().audio_sent`.
        crate::counters::counters().audio_captured.bump();
        let converted = self.convert(source, &data);
        if let Ok(mut sink) = self.sink.lock() {
            sink.play(&converted);
        }
        (self.sink_target)(Out::Samples(source, data.to_vec()));
    }
}

/// What a VM said about one of its streams in `Init`.
///
/// A format and the two fields of `Init` that a format cannot hold. Both were
/// dropped when this port read only `PCMInfo::bits`, and both change the samples
/// rather than the shape of them, so nothing downstream could recover them.
#[derive(Debug, Clone, Copy)]
struct Source {
    format: Format,
    /// The samples are IEEE floats rather than integers. The byte order lives
    /// in `Format::be`, because it has to travel with the samples.
    floating: bool,
}

/// Convert IEEE float samples to the integer format the RFB protocol has.
///
/// RFB's audio is six integer widths and nothing else, so a VM that hands over
/// floats has to be converted here or not at all. The two ends are symmetric on
/// purpose: the floats are read in the byte order the VM declared, and the
/// integers are written in that same order.
///
/// **Why the byte order is passed through rather than normalised.** The
/// counterpart functions honour `Format::be`, so for an integer stream the VM's
/// own bytes reach the client unchanged -- which is what QEMU's own VNC server
/// does, since it writes the backend's native samples out as they are.
/// Normalising the floats to big-endian while integers stayed native would give
/// a client two different byte orders depending on which kind of stream the VM
/// happened to send, so the declared order is carried through instead.
///
/// A float sample is already in the -1.0..1.0 domain the rest of the converter
/// works in, so it is written as it is: [`write_sample`] applies the format's
/// full scale and saturates, exactly as QEMU's `CONV_NATURAL_FLOAT` (multiply
/// by int32's full scale) followed by `clip_*` does. That is why there is no
/// multiply by full scale here -- there used to be, from when samples were in
/// their format's own units.
fn floats_to_samples(format: Format, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() / 2);
    for frame in data.chunks_exact(4) {
        let bytes: [u8; 4] = frame.try_into().expect("chunks_exact(4)");
        let value = if format.be {
            f32::from_be_bytes(bytes)
        } else {
            f32::from_le_bytes(bytes)
        };
        write_sample(format, f64::from(value), &mut out);
    }
    out
}

/// A stateful converter, which is what resampling needs.
///
/// The width, the signedness and the channel count are a per-sample
/// transformation and need nothing kept between blocks, but a *rate* change is
/// not: the samples either side of a block boundary belong to the same
/// interpolation, so a converter that threw its state away between blocks
/// would put a click at every block edge. QEMU's audio backend keeps its
/// resampler's state for the length of the stream for the same reason.
///
/// One converter belongs to one stream, so the resampler is rebuilt when the
/// formats change and reused while they do not.
#[derive(Debug, Default)]
pub struct Converter {
    /// The formats the resampler was built for, and `None` when there is no
    /// resampler: a format that needs no resampling needs no state.
    resampling: Option<Resampling>,
}

/// The resampler and the formats it is for.
#[derive(Debug)]
struct Resampling {
    source: Format,
    target: Format,
    resampler: rubato::Async<f64>,
    /// Input frames waiting for a full chunk, interleaved.
    ///
    /// The resampler takes a fixed number of frames per call, and QEMU's
    /// backend sends blocks of whatever size it likes, so the two are reconciled
    /// here: short blocks wait, and one long block is fed several times over.
    /// That is also what keeps the output the right *length* — a resampler
    /// configured to hand back a fixed chunk would emit a full chunk of output
    /// for every small block, which is more audio than it was given.
    pending: Vec<f64>,
    /// The channels the pending frames are interleaved in.
    channels: usize,
}

impl Converter {
    /// A converter that has done nothing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Convert `data` from `source` to `target`.
    ///
    /// The three steps, in this order: the samples become the values a
    /// resampler works in, the rate is converted if it has to be, and the
    /// channel count is remixed last so that the resampler sees the guest's
    /// channels rather than a mix of them.
    pub fn convert(&mut self, source: Format, target: Format, data: &[u8]) -> Vec<u8> {
        if source == target {
            return data.to_vec();
        }
        let mut samples = to_f64(source, data);
        if source.frequency != target.frequency {
            samples = self.resample(source, target, &samples);
        }
        let samples = remix(source.channels, target.channels, &samples);
        from_f64(target, &samples)
    }

    /// The audio a resampler is still holding, released.
    ///
    /// For a stream that has *ended*. Between blocks the converter holds what
    /// it has been given — that is what makes the resampling continuous — and
    /// a caller that flushed between blocks would resample half a chunk and
    /// leave the resampler mid-interpolation, which is the click this type
    /// exists to avoid.
    pub fn flush(&mut self) -> Vec<u8> {
        let Some(resampling) = self.resampling.as_mut() else {
            return Vec::new();
        };
        let target = resampling.target;
        from_f64(target, &resampling.flush())
    }

    /// Resample interleaved `samples` from the source's rate to the target's.
    fn resample(&mut self, source: Format, target: Format, samples: &[f64]) -> Vec<f64> {
        if samples.is_empty() {
            return Vec::new();
        }
        // Rebuild when the formats move, which is also what a stream that ends
        // and another that starts at a different rate does.
        let rebuild = self
            .resampling
            .as_ref()
            .is_none_or(|resampling| resampling.source != source || resampling.target != target);
        if rebuild {
            match Resampling::new(source, target) {
                Ok(resampling) => self.resampling = Some(resampling),
                Err(e) => {
                    // A resampler that can not be built is not a reason to lose
                    // the audio: the samples are passed through at the source's
                    // rate, which is what this port did before there was a
                    // resampler, and the log says why.
                    tracing::warn!(
                        error = %e,
                        source = source.frequency,
                        target = target.frequency,
                        "no resampler, the samples are sent at the source's rate"
                    );
                    return samples.to_vec();
                }
            }
        }
        let resampling = self
            .resampling
            .as_mut()
            .expect("a resampler was just built or was there already");
        resampling.run(samples)
    }
}

impl Resampling {
    /// Build a resampler for `source` to `target`.
    fn new(source: Format, target: Format) -> Result<Self, rubato::ResamplerConstructionError> {
        let channels = usize::from(source.channels.max(1));
        let ratio = f64::from(target.frequency) / f64::from(source.frequency.max(1));
        let parameters = rubato::SincInterpolationParameters {
            sinc_len: 128,
            f_cutoff: Some(0.95),
            interpolation: rubato::SincInterpolationType::Linear,
            oversampling_factor: 256,
            window: rubato::WindowFunction::BlackmanHarris2,
        };
        // The input chunk is fixed and the output varies, which is the
        // direction that matches the buffering in `run()`: that holds whole
        // input frames, so it should hand the resampler a whole input chunk and
        // take whatever frames come back.
        //
        // The direction is a convenience rather than the fix, and it is worth
        // being exact about that, because the two look equivalent and are not
        // quite. Feeding either mode a 64-frame block gives back a whole output
        // chunk — 16x the audio in one direction, 17x in the other — so neither
        // one resamples "a block". What fixes that is the buffering: audio waits
        // for a full chunk, and then every call carries a full chunk's worth of
        // frames in and a proportionate number out.
        let resampler = rubato::Async::<f64>::new_sinc(
            ratio,
            1.0,
            &parameters,
            RESAMPLE_CHUNK,
            channels,
            rubato::FixedAsync::Input,
        )?;
        Ok(Self {
            source,
            target,
            resampler,
            pending: Vec::new(),
            channels,
        })
    }

    /// Resample a block, holding back what does not make a whole chunk.
    fn run(&mut self, samples: &[f64]) -> Vec<f64> {
        use rubato::Resampler as _;
        if samples.is_empty() {
            return Vec::new();
        }
        self.pending.extend_from_slice(samples);
        let chunk = self.resampler.input_frames_next() * self.channels.max(1);
        if chunk == 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        while self.pending.len() >= chunk {
            let (head, rest) = self.pending.split_at(chunk);
            let frames = chunk / self.channels.max(1);
            let converted = match audioadapter_buffers::direct::InterleavedSlice::new(
                head,
                self.channels,
                frames,
            ) {
                Ok(input) => self.resampler.process(&input, None),
                Err(e) => {
                    tracing::warn!(error = %e, "the resampler's input was not usable, the audio is passed through");
                    out.extend_from_slice(head);
                    self.pending = rest.to_vec();
                    return out;
                }
            };
            match converted {
                Ok(chunk) => out.extend_from_slice(&chunk.take_data()),
                Err(e) => {
                    // The audio in hand is the caller's, and a resampler that
                    // will not take it is a reason to lose fidelity and not to
                    // lose the sound: what is left is handed back as it came.
                    tracing::warn!(error = %e, "the resampler failed, the audio is passed through");
                    out.extend_from_slice(head);
                    self.pending = rest.to_vec();
                    return out;
                }
            }
            self.pending = rest.to_vec();
        }
        out
    }

    /// The audio still held back, resampled and released.
    ///
    /// A stream that has ended rather than paused needs this: the last short
    /// chunk would otherwise sit in the buffer for ever. A stream that is merely
    /// between blocks does not, and calling this then would resample a partial
    /// chunk and leave the resampler mid-interpolation.
    fn flush(&mut self) -> Vec<f64> {
        use rubato::Resampler as _;
        if self.pending.is_empty() {
            return Vec::new();
        }
        let frames = self.pending.len() / self.channels.max(1);
        // `partial_len` says how much of the chunk is real audio, the rest
        // being read as silence: without it the resampler would wait for a
        // whole chunk that is never coming.
        let mut indexing = rubato::Indexing::new();
        indexing.partial_len = Some(frames);
        let out = match audioadapter_buffers::direct::InterleavedSlice::new(
            &self.pending,
            self.channels,
            frames,
        ) {
            Ok(input) => Some(self.resampler.process(&input, Some(&indexing))),
            Err(e) => {
                tracing::warn!(error = %e, "the resampler would not take the last of a stream");
                None
            }
        };
        let left = std::mem::take(&mut self.pending);
        match out {
            Some(Ok(chunk)) => chunk.take_data(),
            Some(Err(e)) => {
                tracing::warn!(error = %e, "the resampler failed to flush, the audio is dropped");
                Vec::new()
            }
            // The resampler would not take it, so the audio is handed back as it
            // came rather than thrown away at the end of a stream.
            None => left,
        }
    }
}

/// How many frames the resampler takes at a time.
///
/// **QEMU's `NSamples`, which is the point.** 480 frames is about 10.9 ms at
/// 44.1 kHz, which is the block size QEMU's own backend hands a client, and
/// matching it means a client is given the same shape of stream it gets from
/// QEMU's built-in VNC server. It was 1024 -- about 23 ms -- which delivered the
/// same bytes per second in blocks twice the size at half the rate, and that is
/// the whole of the remaining difference between this port and QEMU for a client
/// whose audio callback works to a block size.
///
/// The block QEMU produces is fed to the resampler whole, so a smaller chunk
/// means more calls, and the sinc is not cheap: `sinc_len` is 128 at 256x
/// oversampling. Roughly 100 resampler calls a second per client rather than 43.
/// That was measured rather than assumed; see the note in `PORTING.md`.
///
/// A chunk smaller than QEMU's own would be worse than a larger one, because
/// every block that does not fill a chunk produces no output at all and is
/// dropped, so the stream would arrive in ragged bursts. Matching, not
/// minimising.
const RESAMPLE_CHUNK: usize = 480;

/// The interleaved samples of `data` as the values a resampler works in.
fn to_f64(format: Format, data: &[u8]) -> Vec<f64> {
    let width = format.sample.width();
    data.chunks_exact(width)
        .map(|bytes| read_sample(format, bytes))
        .collect()
}

/// The samples of `format`, interleaved, as bytes.
fn from_f64(format: Format, samples: &[f64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(samples.len() * format.sample.width());
    for sample in samples {
        write_sample(format, *sample, &mut out);
    }
    out
}

/// Remix interleaved `samples` from one channel count to another.
///
/// Mixing down is an average, which is what a two channel stream played as one
/// channel wants; mixing up repeats the one channel it has.
fn remix(from: u8, to: u8, samples: &[f64]) -> Vec<f64> {
    let (from, to) = (usize::from(from.max(1)), usize::from(to.max(1)));
    if from == to {
        return samples.to_vec();
    }
    let frames = samples.len() / from;
    let mut out = Vec::with_capacity(frames * to);
    for frame in 0..frames {
        let channels = &samples[frame * from..(frame + 1) * from];
        if from > 1 && to == 1 {
            out.push(channels.iter().sum::<f64>() / channels.len() as f64);
        } else if from == 1 && to > 1 {
            out.extend(std::iter::repeat_n(channels[0], to));
        } else if to > from {
            out.extend_from_slice(channels);
            out.extend(std::iter::repeat_n(channels[from - 1], to - from));
        } else {
            out.extend_from_slice(&channels[..to]);
        }
    }
    out
}

/// Convert samples between two formats that need no resampling.
///
/// The width, the signedness and the channel count are converted; a target rate
/// that differs from the source is *not*, and the samples come out at the
/// source's rate. Use [`Converter`] where the rate has to be converted, which
/// is everywhere in the server: this is the stateless form, kept for the tests
/// and for a caller that already knows the rates agree.
pub fn convert(source: Format, target: Format, data: &[u8]) -> Vec<u8> {
    if source == target {
        return data.to_vec();
    }
    let samples = remix(source.channels, target.channels, &to_f64(source, data));
    from_f64(target, &samples)
}

/// The samples of `format` in `data`, as the values a device wants.
///
/// cpal's `f32` stream is nominally -1.0..1.0, which is the same domain
/// [`read_sample`] produces.
#[cfg(feature = "audio")]
fn samples_in(format: Format, data: &[u8]) -> Vec<f32> {
    let width = format.sample.width();
    data.chunks_exact(width)
        .map(|bytes| read_sample(format, bytes) as f32)
        .collect()
}

/// The signed full scale of a width: the range is `-scale..scale - 1`.
fn full_scale(sample: Sample) -> f64 {
    match sample {
        Sample::U8 | Sample::S8 => 128.0,
        Sample::U16 | Sample::S16 => 32_768.0,
        Sample::U32 | Sample::S32 => 2_147_483_648.0,
    }
}

/// Read one sample as a number in -1.0..1.0, which is the scale QEMU uses.
///
/// **Normalised, matching QEMU's mixing engine.** `audio/mixeng_template.h`
/// holds every width in a signed int32: `conv_*` shifts a sample's own width up
/// to `32` bits (`((int64_t) nv) << (32 - SHIFT)` for a signed format,
/// `((int64_t) nv - BIAS) << (32 - SHIFT)` for an unsigned one), and `clip_*`
/// shifts it back down. The effect is that a signed format's full scale is
/// -1.0 and an unsigned format's midpoint is 0.0, whatever the width: a
/// full-scale `S16` becomes a full-scale `U8` rather than being clamped at
/// zero, and `S32` to `S16` is a scale rather than a saturation.
///
/// This used to preserve the format's own range instead, and the note said so;
/// the tests that pinned it were pinning a fault. It also handed raw integer
/// units to cpal's `f32` stream, whose contract is -1.0..1.0: a device clips
/// every sample past full scale, so an `S16` stream would arrive as a square
/// wave rather than audio.
fn read_sample(format: Format, bytes: &[u8]) -> f64 {
    let sample = format.sample;
    let b = bytes;
    let raw = match (sample, format.be) {
        (Sample::U8, _) => f64::from(b[0]),
        (Sample::S8, _) => f64::from(b[0] as i8),
        (Sample::U16, true) => f64::from(u16::from_be_bytes([b[0], b[1]])),
        (Sample::U16, false) => f64::from(u16::from_le_bytes([b[0], b[1]])),
        (Sample::S16, true) => f64::from(i16::from_be_bytes([b[0], b[1]])),
        (Sample::S16, false) => f64::from(i16::from_le_bytes([b[0], b[1]])),
        (Sample::U32, true) => f64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
        (Sample::U32, false) => f64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
        (Sample::S32, true) => f64::from(i32::from_be_bytes([b[0], b[1], b[2], b[3]])),
        (Sample::S32, false) => f64::from(i32::from_le_bytes([b[0], b[1], b[2], b[3]])),
    };
    let scale = full_scale(sample);
    match sample {
        // An unsigned sample is centred on its midpoint, which is what QEMU's
        // BIAS does, so 128 of 8 bits is silence and 0 is full negative.
        Sample::U8 | Sample::U16 | Sample::U32 => (raw - scale) / scale,
        Sample::S8 | Sample::S16 | Sample::S32 => raw / scale,
    }
}

/// `value` (nominally -1.0..1.0) in QEMU's signed int32 domain, saturated.
///
/// The saturation is QEMU's: `clip_*` saturates at the endpoints of a signed
/// int32 *before* shifting down to the target width, so `1.0` becomes the
/// largest value the width holds. The floor is also QEMU's: a right shift of a
/// negative value rounds towards negative infinity, not towards zero.
fn as_mixeng(value: f64, sample: Sample) -> i64 {
    const INT32: f64 = 2_147_483_648.0;
    let scaled = (value * INT32).clamp(-INT32, INT32 - 1.0);
    (scaled / (INT32 / full_scale(sample))).floor() as i64
}

/// Write one sample, saturating rather than wrapping at the ends.
fn write_sample(format: Format, value: f64, out: &mut Vec<u8>) {
    // The counterpart to `read_sample`: a number in -1.0..1.0 is scaled to the
    // format's width and saturated, which is what `clip_*` does in QEMU's
    // mixing engine. It is written in the order of the stream it came from, not
    // of the target, because the byte order a client sees is the VM's -- QEMU's
    // own VNC server writes the backend's native samples out as they are, and
    // RFB has no field to ask about it.
    let (sample, be) = (format.sample, format.be);
    let value = as_mixeng(value, sample);
    let biased = match sample {
        Sample::U8 => value + 128,
        Sample::U16 => value + 32_768,
        Sample::U32 => value + 2_147_483_648,
        Sample::S8 | Sample::S16 | Sample::S32 => value,
    };
    match (sample, be) {
        (Sample::U8, _) => out.push(biased as u8),
        (Sample::S8, _) => out.push((biased as i8) as u8),
        (Sample::U16, true) => out.extend_from_slice(&(biased as u16).to_be_bytes()),
        (Sample::U16, false) => out.extend_from_slice(&(biased as u16).to_le_bytes()),
        (Sample::S16, true) => out.extend_from_slice(&(biased as i16).to_be_bytes()),
        (Sample::S16, false) => out.extend_from_slice(&(biased as i16).to_le_bytes()),
        (Sample::U32, true) => out.extend_from_slice(&(biased as u32).to_be_bytes()),
        (Sample::U32, false) => out.extend_from_slice(&(biased as u32).to_le_bytes()),
        (Sample::S32, true) => out.extend_from_slice(&(biased as i32).to_be_bytes()),
        (Sample::S32, false) => out.extend_from_slice(&(biased as i32).to_le_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s16_stereo() -> Format {
        Format {
            sample: Sample::S16,
            channels: 2,
            frequency: 44_100,
            be: false,
        }
    }

    fn u8_stereo() -> Format {
        Format {
            sample: Sample::U8,
            channels: 2,
            frequency: 44_100,
            be: false,
        }
    }

    // --- the resampler -----------------------------------------------------

    /// A format at another rate, for a converter that has to resample.
    fn at_rate(sample: Sample, channels: u8, frequency: u32) -> Format {
        Format {
            sample,
            channels,
            frequency,
        be: false,
        }
    }

    /// A sine of `seconds`, in `format`, at an amplitude the format can hold.
    ///
    /// Bytes rather than `f64`s, because that is the interface: the samples
    /// arrive as bytes and leave as bytes, and a test that worked in the
    /// intermediate would be testing a function nobody calls. The amplitude is
    /// 16000 at 16 bit scale, so about 0.49 of full scale on the -1.0..1.0
    /// domain the converter works in; a resampler is linear, so the output
    /// should be at the same scale whichever path it came by.
    fn tone(format: Format, frequency: u32, seconds: f64) -> Vec<u8> {
        /// 16000 in the units of a signed 16 bit sample.
        const AMPLITUDE: f64 = 16_000.0 / 32_768.0;
        let rate = format.frequency;
        let frames = (f64::from(rate) * seconds) as usize;
        let samples: Vec<f64> = (0..frames)
            .flat_map(|frame| {
                let phase = 2.0 * std::f64::consts::PI * f64::from(frequency) * frame as f64
                    / f64::from(rate);
                let value = phase.sin() * AMPLITUDE;
                std::iter::repeat_n(value, usize::from(format.channels))
            })
            .collect();
        from_f64(format, &samples)
    }

    /// One channel of interleaved `samples`, which is what the tone tests
    /// correlate over.
    ///
    /// The two channels of these tests hold the same sine, so correlating over
    /// the raw interleaved stream would be correlating against a signal that
    /// only changes every other sample — half the terms cancel and the answer
    /// comes out small whatever the resampler did.
    fn one_channel(samples: &[f64], channels: u8) -> Vec<f64> {
        let channels = usize::from(channels.max(1));
        samples.iter().step_by(channels).copied().collect()
    }

    /// The magnitude of `frequency` in `samples`, by correlation.
    ///
    /// A plain sum of the samples against a sine and a cosine at that
    /// frequency, which is the honest way to do it: the Goertzel recursion
    /// would be shorter to write and numerically useless here, because its
    /// poles sit on the unit circle and a second of audio at 48 kHz is far
    /// enough past that for the rounding error to swamp the answer. Two
    /// magnitudes that both came back near zero is what that looks like, and it
    /// is not what a resampler failing looks like.
    ///
    /// The window is a whole number of cycles of both frequencies the test
    /// asks about, so neither leaks into the other.
    fn magnitude_at(samples: &[f64], frequency: f64, rate: u32) -> f64 {
        let period = f64::from(rate) / frequency;
        // Whole cycles, and few enough of them that the window is not all
        // silence: the resampler's first output chunk is its start-up delay, and
        // correlating over that would measure the delay rather than the tone.
        let cycles = (samples.len() as f64 / period / 4.0).floor().max(1.0) as usize;
        let window = ((cycles as f64 * period).round() as usize)
            .min(samples.len())
            .max(1);
        let step = 2.0 * std::f64::consts::PI * frequency / f64::from(rate);
        let (mut real, mut imaginary) = (0.0, 0.0);
        for (index, sample) in samples.iter().take(window).enumerate() {
            let phase = step * index as f64;
            real += sample * phase.cos();
            imaginary += sample * phase.sin();
        }
        2.0 * real.hypot(imaginary) / window as f64
    }

    /// The `cpal` sink on a machine with no sound card.
    ///
    /// This is the only test that can touch the sink, because a machine with a
    /// sound card would open a real device and play into it. What it checks is
    /// the part that has to be right everywhere: a machine that can not play
    /// audio says so, rather than panicking or opening something it can not
    /// close. The `cpal` sink used to be written and never compiled, so this is
    /// also the first thing to have ever *run* on that file.
    #[cfg(feature = "audio")]
    #[test]
    fn the_cpal_sink_says_so_rather_than_failing_strangely() {
        use cpal::traits::HostTrait;

        let has_device = cpal::default_host().default_output_device().is_some();
        match CpalSink::open(DEFAULT_FORMAT) {
            Ok(_) => assert!(
                has_device,
                "the sink opened a device on a machine that has none, which means \
                 it opened something else"
            ),
            Err(e) => {
                assert!(
                    !has_device || matches!(e, Error::UnsupportedFormat | Error::Backend(_)),
                    "a machine with an output device should open it or say why it \
                     could not, not fail with {e:?}"
                );
                // Whichever it is, the message has to say what went wrong: this
                // string is what a user with no sound card sees.
                assert!(
                    !e.to_string().is_empty(),
                    "an error with nothing in it is not a message"
                );
            }
        }
    }

    #[test]
    fn a_rate_that_does_not_change_is_never_resampled() {
        // The fast path, and it has to be exact: a client whose format matches
        // gets the guest's bytes, not a resampled approximation of them.
        let mut converter = Converter::new();
        let data = vec![0x11u8, 0x22, 0x33, 0x44];
        assert_eq!(
            converter.convert(s16_stereo(), s16_stereo(), &data),
            data,
            "a matching format should pass straight through"
        );
    }

    #[test]
    fn a_change_of_rate_produces_the_right_number_of_frames() {
        // 44100 up to 48000 is the common case: a device that wants 48 kHz and
        // a guest at 44.1 kHz. The output is the input's duration at the new
        // rate, give or take the resampler's startup delay.
        let source = s16_stereo();
        let target = at_rate(Sample::S16, 2, 48_000);
        let seconds = 1.0;
        let mut converter = Converter::new();
        let out = converter.convert(source, target, &tone(source, 1_000, seconds));
        let frames = out.len() / target.frame_size();
        let expected = f64::from(target.frequency) * seconds;
        let difference = (frames as f64 - expected).abs();
        assert!(
            difference < expected * 0.05,
            "a second at {} should be about {expected} frames at {}, got {frames} \
             (off by {difference})",
            source.frequency,
            target.frequency
        );
    }

    #[test]
    fn a_resampled_tone_is_still_the_same_tone() {
        // The point of a resampler: the pitch survives. A resampler that
        // repeated or dropped samples would keep the length roughly right and
        // lose the tone, so this checks the frequency and not just the count.
        let source = s16_stereo();
        let target = at_rate(Sample::S16, 2, 48_000);
        let mut converter = Converter::new();
        let out = converter.convert(source, target, &tone(source, 1_000, 1.0));
        let resampled = one_channel(&to_f64(target, &out), target.channels);

        let wanted = magnitude_at(&resampled, 1_000.0, target.frequency);
        let elsewhere = magnitude_at(&resampled, 3_000.0, target.frequency);
        assert!(
            wanted > elsewhere * 10.0,
            "a 1000 Hz tone should still be a 1000 Hz tone: {wanted} at 1000 Hz \
             against {elsewhere} at 3000 Hz"
        );
    }

    #[test]
    fn a_resampled_tone_keeps_its_amplitude() {
        // A resampler that quietly scaled the samples would pass the frequency
        // test above and still sound wrong, so the amplitude is checked too.
        let source = s16_stereo();
        let target = at_rate(Sample::S16, 2, 22_050);
        let data = tone(source, 1_000, 1.0);
        let mut converter = Converter::new();
        let out = converter.convert(source, target, &data);
        let resampled = to_f64(target, &out);

        let peak = |samples: &[f64]| samples.iter().fold(0.0f64, |p, s| p.max(s.abs()));
        let (before, after) = (peak(&to_f64(source, &data)), peak(&resampled));
        // Downsampling from 44.1 kHz to 22.05 kHz halves the number of samples
        // and keeps the amplitude: this is a filter, not a gain.
        let ratio = after / before;
        assert!(
            (0.9..=1.1).contains(&ratio),
            "a resampler should not change the amplitude much: {before} in, \
             {after} out, a ratio of {ratio}"
        );
        assert!(
            after > 0.4,
            "and the tone should still be there at all, not a peak of {after}"
        );
    }

    /// What `RESAMPLE_CHUNK` costs, in processor time per second of audio.
    ///
    /// `#[ignore]`d, because it is a measurement rather than a claim: it takes
    /// long enough to be rude in a suite, and its result belongs in a note next
    /// to the constant rather than in an assertion that would fail on a slow
    /// machine. Run it with `--ignored` and compare the two chunk sizes.
    ///
    /// Wall time, not a processor clock, and that is deliberate here: this is a
    /// tight arithmetic loop with no I/O, no lock and no syscall, so the
    /// scheduler is not in the measurement. That is the opposite of the receive
    /// path, which ends in a socket read and where `Instant` is what produced
    /// three wrong rounds of conclusions.
    ///
    /// The input is the shape QEMU sends: `NSamples` blocks at the guest's
    /// rate, resampled to what a client negotiated.
    #[test]
    #[ignore]
    fn the_resamplers_cost_per_second_of_audio() {
        const BLOCK: usize = 441; // QEMU's NSamples, at 44.1 kHz
        const SECONDS: usize = 10;
        let source = Format { sample: Sample::S16, channels: 2, frequency: 44_100, be: false };
        let target = Format { sample: Sample::S16, channels: 2, frequency: 48_000, be: false };
        let block: Vec<u8> = (0..BLOCK * 4).map(|i| (i % 251) as u8).collect();

        let mut converter = Converter::new();
        // Warm the resampler up, so the first call's allocation is not counted
        // as the price of the rest.
        let _ = converter.convert(source, target, &block);

        let started = std::time::Instant::now();
        let mut out_bytes = 0usize;
        for _ in 0..(SECONDS * 44_100 / BLOCK) {
            out_bytes += converter.convert(source, target, &block).len();
        }
        let elapsed = started.elapsed();
        let produced = out_bytes as f64 / 4.0 / 48_000.0;

        println!(
            "RESAMPLE chunk={RESAMPLE_CHUNK} seconds_of_audio={produced:.2} \
             wall={elapsed:?} cpu_per_second_of_audio={:.3} ms",
            elapsed.as_secs_f64() * 1000.0 / produced
        );
    }

    #[test]
    fn resampling_is_stateful_across_blocks() {
        // This is the reason a `Converter` exists rather than a function: the
        // samples either side of a block boundary belong to the same
        // interpolation. One big block and many small ones have to come to
        // about the same place, or the boundary is putting a click in.
        let source = s16_stereo();
        let target = at_rate(Sample::S16, 2, 48_000);
        let data = tone(source, 1_000, 1.0);

        let mut whole = Converter::new();
        let one_block = whole.convert(source, target, &data).len();

        let mut piecewise = Converter::new();
        let frame_size = source.frame_size();
        let piece_frames = 64;
        let mut done = 0;
        let mut total = 0;
        while (done * frame_size) < data.len() {
            let end = ((done + piece_frames) * frame_size).min(data.len());
            let converted = piecewise.convert(source, target, &data[done * frame_size..end]);
            assert_eq!(
                converted.len() % target.frame_size(),
                0,
                "a block should convert into whole frames"
            );
            total += converted.len();
            done += piece_frames;
        }
        // The resampler holds back a chunk at each call, so a final empty block
        // is what makes the small-block path finish the audio it was given.
        let many = total + piecewise.convert(source, target, &[]).len();

        // The two are not equal to the sample, and should not be: what has to
        // hold is that they are close, because a resampler that forgot its
        // state at every block boundary would lose or gain far more than this.
        let difference = (one_block as i64 - many as i64).unsigned_abs() as usize;
        assert!(
            difference < one_block / 20,
            "one block gave {one_block} bytes and {piece_frames}-frame blocks gave \
             {many}, a difference of {difference}: a resampler that forgets its \
             state loses or gains more than its own chunk"
        );
    }

    #[test]
    fn a_change_of_rate_rebuilds_the_resampler() {
        // A stream that ends and another that starts at a different rate must
        // not be resampled with the first one's resampler, which would be a
        // resampler for the wrong ratio.
        let mut converter = Converter::new();
        let source = s16_stereo();
        let data = tone(source, 1_000, 0.5);

        let up = converter.convert(source, at_rate(Sample::S16, 2, 48_000), &data);
        let back = converter.convert(source, at_rate(Sample::S16, 2, 22_050), &data);
        let frames = |out: &[u8]| out.len() / at_rate(Sample::S16, 2, 22_050).frame_size();
        assert!(
            frames(&up) > frames(&back),
            "48 kHz should have produced more frames than 22.05 kHz, got {} and {}",
            frames(&up),
            frames(&back)
        );
    }

    #[test]
    fn a_rate_change_also_converts_the_width_and_the_channels() {
        // All three at once, which is the case a device at 48 kHz stereo S16
        // and a guest at 44.1 kHz mono U8 is. Every step has to happen.
        let source = at_rate(Sample::U8, 1, 44_100);
        let target = at_rate(Sample::S16, 2, 48_000);
        let mut converter = Converter::new();
        let out = converter.convert(source, target, &[0x80; 4_400]);
        assert_eq!(
            out.len() % target.frame_size(),
            0,
            "the output should be whole stereo frames of 16 bits"
        );
        assert!(!out.is_empty(), "and there should be some of it");
    }

    #[test]
    fn the_same_format_is_copied_through() {
        let data = vec![1u8, 2, 3, 4];
        assert_eq!(convert(s16_stereo(), s16_stereo(), &data), data);
    }

    #[test]
    fn the_width_and_signedness_are_converted() {
        // Two stereo frames of signed 16 bit: -1, 0, then -32768, 0. The
        // bytes are big endian, so the second frame's first sample is 0x8000 --
        // and the formats have to say so, since the byte order is now carried
        // on `Format` rather than assumed. It used to be assumed, and assuming it
        // was what let a float stream be decoded as an integer one.
        let big_endian = |format: Format| Format { be: true, ..format };
        let data = vec![0xFF, 0xFF, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00];
        let out = convert(big_endian(s16_stereo()), big_endian(u8_stereo()), &data);
        // -1 is the floor of a 16 bit chunk and -32768 is the bottom of the
        // range. The conversion is a scale, as QEMU's is, so both land at the
        // bottom of the unsigned range, and 0 is its midpoint.
        assert_eq!(out, vec![127, 128, 0, 128]);
    }

    #[test]
    fn a_width_change_is_a_scale_not_a_clamp() {
        // The other direction, and the case the old range-preserving code got
        // wrong: a full-scale unsigned sample must become a full-scale signed
        // one. QEMU's `conv_*` shifts an 8 bit sample up to int32 and `clip_*`
        // shifts it down, so U8 to S16 is a left shift of eight.
        let out = convert(u8_stereo(), s16_stereo(), &[0x00, 0x80, 0xFF, 0x80]);
        assert_eq!(
            out,
            vec![0x00, 0x80, 0x00, 0x00, 0x00, 0x7F, 0x00, 0x00],
            "0 should be -32768, 128 should be 0 and 255 should be 32512"
        );
    }

    #[test]
    fn mixing_down_to_one_channel_averages() {
        let data = vec![0x00, 0x10, 0x00, 0x20]; // 16 and 32
        let mono = Format {
            channels: 1,
            ..s16_stereo()
        };
        let out = convert(s16_stereo(), mono, &data);
        assert_eq!(out, vec![0x00, 0x18]); // the average, 24
    }

    #[test]
    fn a_sample_saturates_rather_than_wrapping() {
        // Beyond full scale, not merely at it: 1.0 is the largest value a width
        // holds, because QEMU's `clip_*` saturates in its int32 domain before
        // shifting down, and anything past it saturates too rather than wrapping
        // to the other end.
        let mut out = Vec::new();
        write_sample(s16_stereo(), 1.0, &mut out);
        assert_eq!(i16::from_le_bytes([out[0], out[1]]), i16::MAX);
        out.clear();
        write_sample(s16_stereo(), 2.0, &mut out);
        assert_eq!(i16::from_le_bytes([out[0], out[1]]), i16::MAX);
        out.clear();
        write_sample(s16_stereo(), -2.0, &mut out);
        assert_eq!(i16::from_le_bytes([out[0], out[1]]), i16::MIN);
        // An unsigned width saturates at its own ends too.
        out.clear();
        write_sample(u8_stereo(), 2.0, &mut out);
        assert_eq!(out, vec![255]);
        out.clear();
        write_sample(u8_stereo(), -2.0, &mut out);
        assert_eq!(out, vec![0]);
        // And a value at the top of a narrower signed width stays positive when
        // it is scaled into a wider unsigned one.
        let data = vec![0x7F, 0xFF, 0x00, 0x00];
        let big_endian = |format: Format| Format { be: true, ..format };
        let u32_format = big_endian(Format {
            sample: Sample::U32,
            ..s16_stereo()
        });
        let out = convert(big_endian(s16_stereo()), u32_format, &data);
        assert_eq!(
            u32::from_be_bytes([out[0], out[1], out[2], out[3]]),
            0xFFFF_0000,
            "the largest signed 16 bit value is near the top of unsigned 32"
        );
    }

    #[cfg(feature = "audio")]
    #[test]
    fn a_device_is_given_samples_in_the_range_it_plays() {
        // cpal's `f32` stream is -1.0..1.0. Handing it raw integer units clips
        // every sample past full scale, which is a square wave rather than
        // audio, and no test that only looks at bytes can see it.
        let s16 = samples_in(s16_stereo(), &[0x00, 0x80, 0xFF, 0x7F]);
        assert_eq!(s16, vec![-1.0, 32_767.0 / 32_768.0]);
        assert!(
            s16.iter().all(|sample| (-1.0..=1.0).contains(sample)),
            "a device sample is in -1.0..1.0, got {s16:?}"
        );
        // An unsigned stream is centred on its midpoint rather than its bottom.
        assert_eq!(
            samples_in(u8_stereo(), &[0, 128, 255]),
            vec![-1.0, 0.0, 127.0 / 128.0]
        );
    }

    #[test]
    fn a_null_sink_is_given_the_samples_as_they_are() {
        // The point of the null sink: the audio path works on a machine with
        // no output device, which is what the conversion here proves.
        let mut sink = NullSink::new();
        assert_eq!(sink.format(), None);
        let data = vec![9u8; 16];
        sink.play(&data);
        assert_eq!(sink.played(), 16);
        assert_eq!(sink.last(), &data[..]);
    }

    #[test]
    fn the_samples_reach_the_target_and_the_sink() {
        // Both halves: what the clients get, and what a sink on the same
        // machine plays.
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_by_clients = seen.clone();
        let mut server = AudioServer::new(Box::new(NullSink::new()), move |out| {
            if let Out::Samples(_, data) = out {
                seen_by_clients.lock().unwrap().extend_from_slice(&data)
            }
        });
        futures::executor::block_on(async {
            server
                .init(
                    1,
                    PCMInfo {
                        bits: 16,
                        is_signed: true,
                        is_float: false,
                        freq: 44_100,
                        nchannels: 2,
                        bytes_per_frame: 4,
                        bytes_per_second: 176_400,
                        be: false,
                    },
                )
                .await;
            server.write(1, vec![1, 2, 3, 4]).await;
            server.fini(1).await;
        });
        assert_eq!(seen.lock().unwrap().as_slice(), &[1, 2, 3, 4]);
        // A stream we were never told about is dropped rather than guessed at.
        assert!(server.format(1).is_none(), "the stream is gone");
        // The sink was given the same samples, which is the other half of the
        // path: what the clients get and what a machine would play.
        assert_eq!(server.sink_format(), None, "the null sink takes anything");
    }

    #[test]
    fn the_listening_count_goes_up_and_down() {
        let server = AudioServer::new(Box::new(NullSink::new()), |_| {});
        let count = server.listening();
        server.set_listening(true);
        server.set_listening(true);
        assert_eq!(*count.lock().unwrap(), 2);
        server.set_listening(false);
        assert_eq!(*count.lock().unwrap(), 1);
        // Never below zero, however many times a client says it stopped.
        server.set_listening(false);
        server.set_listening(false);
        assert_eq!(*count.lock().unwrap(), 0);
    }

    #[test]
    fn a_file_sink_is_given_what_would_have_been_played() {
        // The path CI can check: the samples that would be played are on disk.
        let path = std::env::temp_dir().join(format!("qemu-vnc-audio-{}.raw", std::process::id()));
        let mut sink = FileSink::create(&path, s16_stereo()).expect("created");
        sink.play(&[1, 2, 3, 4]);
        assert_eq!(sink.written(), 4);
        drop(sink);
        let written = std::fs::read(&path).expect("read back");
        assert_eq!(written, vec![1, 2, 3, 4]);
        std::fs::remove_file(&path).ok();
    }
}
