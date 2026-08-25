# QEMU D-Bus display experiment

## Introduction

*WIP* Rust crates to interact with a ``-display dbus`` QEMU.
Some dependencies, such as RDW are also in development and unreleased.

## Features

Depending on what the VM exposes & supports, various interfaces are implemented:

 - display, with optional DMABUF sharing
 - display resize
 - keyboard & mouse
 - serial terminals
 - QMP/HMP monitors
 - audio playback & recording
 - USB device redirection
 - clipboard sharing

## Project organization

### qemu-display

This crate provides simple D-Bus interfaces through zbus, and some basic abstractions.

### qemu-rdw

This crate provides a demo app for `rdw4-qemu` from "[rdw](https://gitlab.gnome.org/malureau/rdw)"
(*Remote display/desktop widget*).

### qemu-vnc

A simple VNC server implementation.

### qemu-vte

A standalone VTE/Gtk+ 4 client, which should eventually be a consumable crate or
integrated with qemu-rdw.

## Build requirements

To build this project, you will need several system libraries. Here is the
current list of build dependencies on Fedora:

```sh
$ sudo dnf install cargo gcc usbredir-devel wayland-devel libxkbcommon-devel glib2-devel gtk4-devel gstreamer1-devel gstreamer1-plugins-base-devel
```
