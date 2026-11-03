# Recovery of `tests/mock.rs`

`tests/mock.rs` was 4,234 lines and was destroyed on 2026-09-28 by a script of
mine: `open(dst,"w").write(open(dst).read())` truncates the file before the read
returns. It was untracked, so git never had a copy.

**It has been rebuilt and is in place.** `tests/mock.rs` is now 4,246 lines with
57 tests, all passing, and the whole suite is green: 227 passed, 0 failed across
14 binaries, no warnings. This directory holds the machinery and the evidence; the test file
itself is not here.

64 of the 65 names in `known-test-names.txt` are present; the one that is not was
deliberately replaced in the original session — see below. **That list is not
complete**, as the next section shows: the file had at least one more test that
no pre-truncation binary ever carried a symbol for.

## How it came back

The opencode session database (`opencode.db`) records the file's whole
construction. Not as snapshots — as the *operations*, which is better: 299
events in the order the session made them.

| mechanism | count | content in the record |
| --- | --- | --- |
| whole-file `write` | 2 | `state.input.content`, exact |
| `edit` | 61 | `oldString` / `newString`, exact |
| `cat >> ... <<'RSEOF'` | 19 | the heredoc body, verbatim |
| `python3 - <<'PY'` | ~197 | the script body, executed |
| `python3 -c "..."` | 23 | executed after rewriting the `cd` |
| `sed -i` | 4 | executed |

`replay.py` applies them in order inside a scratch tree (`/tmp/opencode/replayroot`)
and never touches the repository. The first event's content is md5-identical to
`mock.legacy.rs`, which is the file's first iteration.

Three things had to be fixed before the replay was usable, each found by
measurement rather than reasoning:

1. **Path rewriting.** Rewriting `/tmp/opencode/` into the scratch root *and*
   then the project path made the second rewrite match the first one's output, so
   every command ran as `cd /tmp/opencode/replayroot/tmp/replayroot` and silently
   did nothing. One `re.sub` pass, not chained `str.replace`.
2. **Two spellings of every path.** 28 of the original scripts were run from
   `qemu-vnc/` and the rest from the project root, so choosing one working
   directory broke the others — 36 failures, all `FileNotFoundError` on files
   that plainly existed. The scratch root now carries union symlinks (`tests`,
   `src`, `examples`, ...) so both spellings resolve and there is one cwd.
3. **Edits whose `oldString` no longer matched.** Applied by line-level hunks
   anchored on a unique run of the old text. One of those spliced two test bodies
   together; `balance.py` is the guard that catches it — a Rust-aware
   delimiter-balance check, validated on 54 repository files that certainly
   balance. It rejects any edit that would leave the file unbalanced and rolls
   it back.

## Repairs applied to the replayed file

Seven, each traceable to a recorded migration or to surviving source. Nothing
here is invention.

| # | site | change | evidence |
| --- | --- | --- | --- |
| 1 | `request_until` call, scanout test | closure form to `&frame()` | recorded migration, tm 1790680509685, verbatim |
| 2 | `request_until` call, damage test | closure form to `&[0x11,0x22,0x33,0x00]` | same migration; the bytes are what the following `assert_eq!` compares |
| 3 | `mock.update((10,10,1,1), …)` | insert `FIRST` | recorded migration tm 1790680871189; its pattern `"mock.update(\n"` only matched a call split across lines, which the replay's text is not |
| 4 | `wait_for` on the clipboard | added `"saw the clipboard reach the client"` | recorded migration tm 1790683226195 |
| 5 | `wait_for` on the grab | added `"saw the client grab the clipboard"` | recorded migration tm 1790683239078 |
| 6 | `audio_server` closure | `\|samples\|` to a `match` over `audio::Out` | `src/audio.rs:376` takes `Fn(Out)`; `server/mod.rs:434,443` take `(source, samples)` and `()` |
| 7 | duplicate `start_audio` | removed the pre-refactor copy | the surviving one delegates to `start_audio_in`, which the refactor introduced |

Then one test's own expectation, which was wrong: `a_key_from_the_client_arrives_at_the_console`
asserted keycode `30` for keysym `0x41` with the comment "30 the QEMU keycode for
it". That is the falsified check that passed while the keyboard bug was live. A
QEMU key number is the Linux evdev code **plus 8** — `qemu-vnc/c/input.c` sends
`qemu_input_map_linux_to_qnum[lnx]` — so it is 38, and `0x42` is 56, not 48.
The expectation and the comment were both corrected.

## What it does not restore

One of the 65 known names is absent, and its absence is correct.

`a_console_that_draws_after_the_client_asked_still_reaches_it` **was replaced in
place** at tm 1790782487347 by a script that finds the function, backs up over its
`#[test]` and doc comment, and substitutes `a_console_that_draws_is_not_answered_without_a_request`
in its place. The replacement's own doc comment says why:

> An earlier version of this test asserted the opposite, on the strength of a
> comment here that read "the client is in the incremental state its last request
> left it in" as though the state persisted. It does not; the line above clears it.

The two tests assert opposite behaviour — the old one required the server to push
a frame with no request outstanding, which `ui/vnc.c` does not do. So the name
appears in the database, was a real test, and was deliberately retired. An earlier
draft of this file listed it as a loss; that was wrong.

Two more were initially assumed lost for the wrong reason. They exist in the
database, intact and complete, and both were recovered and put back:

- `damaged_regions_that_touch_are_merged_into_one` — appended by a
  `cat >> … <<'RSEOF'` at tm 1790785245175. Its own doc comment records that it
  "found that `touches` was untested", and it does catch that: with
  `Rect::touches` mutated to merge on overlap only, it is the **only** test in
  the suite that fails.
- `a_client_that_asks_for_no_compression_gets_raw_pixels` and
  `a_client_that_asks_for_no_compression_is_never_given_any` — see below. Adding
  them exposed a live regression.

## The regression the recovered tests found

The two compression-policy tests passed at tm 1790834671525. `codec_for_preference`
was introduced at tm 1790859427963 — the change that made "the client's stated
encoding preference wins over this port's ladder" — and at tm 1790859826380
`a_client_that_asks_for_no_compression_is_never_given_any` was recorded **FAILED**.
No fix appears anywhere in the record; the file was truncated shortly after.

The cause was visible in the source as a self-contradiction. `Policy::choose`
lowers its ceiling when the client asked for no compression:

```rust
if let Some(wanted) = self.wanted {
    self.ceiling = self.ceiling.min(Self::ceiling_of_level(wanted));
}
```

and its comment says "a client that says it wants no compression gets raw pixels
even when the link is fast and the encodings are on offer". But it then calls
`codec_for_preference(self.level, …)`, whose preferred arms (`Some(Codec::Tight)`,
`Some(Codec::Zrle)`, …) never consult `level` — it is used only in the `_`
fallback. So a client that listed Tight first *and* asked for level 0 was given
Tight. `want_compression`'s doc said this outright: "a client that asks for no
compression … gets the exact opposite of what it asked for".

The fix is four lines in `Policy::choose`: an explicit `self.wanted == Some(0)`
returns `Codec::Raw` before the preference is consulted. It is deliberately
narrow — it does not disturb the existing behaviour where a small rectangle's
ceiling is `LEVEL_RAW` and a Tight preference still wins.

Removing it again fails exactly two tests, `…_gets_raw_pixels` and
`…_is_never_given_any`, and nothing else in the suite.

## The 66th test, and `counter_test.rs`

`/tmp/opencode/counter_test.rs` was described in an earlier draft of this file as
"never captured". That was wrong, twice over. It exists in the record, it was
*created* there, and its content is present.

It was not written by hand. At tm 1790804203250 a script inserted the block into
`qemu-vnc/src/server/client.rs` inside `mod convert_tests`, with its body inline in
a `t = '''…'''` literal. At tm 1790804227189 a second script carved that same block
back out, between two doc-comment markers, into `counter_test.rs`. At
tm 1790804268008 a third script inserted it into `tests/mock.rs` before an anchor
and printed `inserted into mock.rs`; the very next command's output is
`test the_counters_cover_the_encode_and_the_rest_of_the_thread ... ok`.

So the test existed, passed, and was in the file when it was destroyed. It is
absent from `known-test-names.txt` because that list came from one pre-truncation
test binary's `--list` and the incremental cache's object files, and that binary
predates the insertion. **The 65-name list is a lower bound, not the file's
test count** — which is worth knowing before treating it as the target.

Recovered and restored. It is load-bearing: with `idle_nanos` never bumped, it is
the only test in the suite that fails.

## What was removed, and the evidence for it

`dbg_request_rate_versus_updates_delivered` was recovered from the record and
then **removed**. The record shows it was appended at tm 1790762355757 and ran:
`1 passed … 36 filtered out`, so 37 tests at that moment. Yet it is in **none** of
the nine pre-deletion `mock-*` binaries, including the ones built an hour later
with 38 tests. A test that passed cannot vanish from every later build without
being removed, and the only `cp`-into-`mock.rs` events on record are my own from
2026-10-02. It was `QEMU_VNC_BENCH`-gated, so it returned immediately and passed
vacuously in any normal run.

There is no recorded removal event for it, so this rests on absence across nine
binaries rather than a documented deletion. That is an inference, and it is
recorded here as one.

`damaged_regions_that_touch_are_merged_into_one` was kept, on the opposite and
stronger evidence: it is listed by `mock-43c5b51724c8ffb3` (09-30 18:55) and
`mock-95bef99ebacf46e4` (09-30 18:56), both pre-deletion.

## Why no test count from the object files

The 763 objects of the `7104949d1f514958` build are **not** a coherent snapshot
and cannot supply a test count. Only 43 of them carry any `mock::` code, spread
across six timestamps from 09-30 23:20 to 10-01 18:24, because cargo reused the
dep-info hash across many incremental builds. Taking the newest object per unit
mixes those moments. The proof that it misleads: it contains neither
`damaged_regions_that_touch_are_merged_into_one` — which two pre-deletion
binaries show was present — nor `dbg_request_rate_versus_updates_delivered`.

`known-test-names.txt` is likewise not a count of the file: 49 of its 65 entries
are tests and 16 are helpers. Its test names come from `--list` on nine binaries
whose newest is 09-30 20:45, and its single incremental-unit `nm` source
contributed **no** test names at all — only helpers.

## The last two tests, and a defect the restore exposed

`a_reference_client_can_read_our_tight_at_productions_size` and
`…_zrle_at_productions_size` are not two independent tests. The Tight one is an
80-line body (tm 1790875315410); tm 1790875400602 is a **refactor** whose four
`s.replace` calls lift that body into a shared `async fn size_witness(encoding)`
and rewrite both tests to call it. Applying those four recorded replacements
verbatim reproduces the pair. Two helpers were missing as well —
`vncrs_witness()` (tm 1790868926346) and `size_witness` — so the tests could not
have compiled without them either.

**As recorded, both tests did nothing.** `size_witness` is `async fn` and the
tests called it bare, so the future was built and dropped:

```
warning: unused implementer of `futures::Future` that must be used
1961 |     size_witness("tight");
```

The record shows the same defect: that refactor's own run reported
`2 passed … finished in 0.00s`. Both now go through `async_io::block_on`, which
is how every other async helper in this file is called, and they finish in 0.78 s
reaching `VERDICT: ok` through the independent decoder.

They are load-bearing. Truncating `tight_full_color`'s packed buffer by three
bytes gives `VERDICT: error`, the Tight test fails, and **the ZRLE control stays
green** — which is the discrimination the pair exists for: "Without this, 'Tight
failed at 1280x800' does not mean Tight is wrong."

## The remaining gap

The file is 4,246 lines against an original 4,234 — twelve lines *over*, which is
the two helpers and two tests having been recovered after the line-count
comparison was first made. Both named tests from the previous revision are now
present. What remains unreconciled is edits keyed on text the replay renders
differently, plus their commentary.

The line count is a weak measure here and should not be treated as a target: both
name lists proved to be lower bounds, so content may be present in different
wording.

`damage_tests.rs`, `fix_clip.py` and `mock_more.py` were recovered from the record
and used. No external content file remains missing.

## Evidence that the tests are not vacuous

57 tests, 52 substantive. Five return early unless an environment variable is
set, and so pass vacuously in a normal run — `QEMU_VNC_SERVE`,
`QEMU_VNC_REFCLIENT`, `QEMU_VNC_BENCH`. That is by design (they need an external
client or a benchmark flag) but it should be stated rather than counted as
coverage.

Four mutations were applied to the implementation and reverted. Each was caught,
on four independent axes:

| mutation | tests that failed |
| --- | --- |
| `LINUX_TO_QNUM_OFFSET` 8 → 0 | 1 |
| `set_scanout` reports no damage | 5 |
| `set_update` reports the whole console regardless of the comparison | 7 |
| `compress_prefixed` reserves 4 header bytes instead of 3 | 3 |
| `Rect::touches` merges on overlap only, dropping adjacency | 1 |
| `Policy::choose`'s level-0 guard removed | 2 |
| `idle_nanos` never bumped | 1 |

One earlier attempt appeared to escape: making `set_scanout` report a full
repaint passed all 52. That was my error — the tests that check damage
granularity drive `mock.update`, which is `set_update`, not `set_scanout`.
Mutating the right function caught 7.

## Files here

- `replay.py` — the replay, with the three fixes above
- `balance.py` — the delimiter-balance oracle used to reject splices
- `known-test-names.txt` — 65 function names, from the pre-truncation test
  binary's `--list` and the incremental cache's object files
- `mock.cp-backup-1813-lines.rs` — a genuine `cp` snapshot recovered from the
  record. Not a copy of the reconstruction: no replay snapshot is byte-identical
  to it, and the replay's file was 2,186 lines when that `cp` ran while this is
  1,813. It is not clean either — it fails to build with 14 errors, including
  `the name 'start_audio' is defined multiple times`, so it was taken mid-edit.
  Kept as evidence, not as a source.