---
title: "Vulnerability root-cause analysis on Linux"
date: 2026-01-15
draft: false
weight: 1
---

## Introduction

As you may know: finding bugs is one of the greatest things in life — but once you finally obtain the precious memory corruption you were praying for, you still need to actually understand it.

In this article we’ll explore how to conduct a root-cause analysis of a vulnerability in a Linux open-source program that we compiled ourselves. That matters because it lets us **disable stripping** and **enable debug symbols**, which makes the investigation dramatically easier.

We’ll start by installing a GDB extension called **pwndbg**. It not only prettifies `gdb` output, it also provides a lot of handy commands and helpers.

- Pwndbg: https://pwndbg.re/pwndbg/latest

---

## The bug

I recently discovered a vulnerability while fuzzing **FFmpeg**.

- FFmpeg: https://ffmpeg.org/

To follow along, compile FFmpeg with debug symbols and without stripping (e.g. `-g` and no `strip`). Then run the crashing file under pwndbg:

```bash
$ pwndbg ./ffmpeg
$ start "-i bug_triggering_file -f null -"
````

`start` sets a temporary breakpoint in `main`, runs until that breakpoint, and stops. Now run:

```bash
$ continue
```

At this point the program executes and eventually crashes:

```text
ffmpeg version N-121008-gf4b044bbe3 Copyright (c) 2000-2025 the FFmpeg developers
  built with Ubuntu clang version 18.1.3 (1ubuntu1)
[mjpeg @ 0x519000001480] not enough bytes remaining in EXIF buffer. entries: 16752
Input #0, jpeg_pipe, from 'bug_triggering_file':
  Duration: N/A, bitrate: N/A
  Stream #0:0: Video: mjpeg (Baseline), yuvj420p(pc, bt470bg/unknown/unknown)
Stream mapping:
  Stream #0:0 -> #0:0 (mjpeg (native) -> wrapped_avframe (native))
[New Thread 0x7ffff1dff6c0 (LWP 197316)]
[New Thread 0x7ffff15fe6c0 (LWP 197317)]
[New Thread 0x7ffff02f46c0 (LWP 197318)]
[New Thread 0x7fffeefea6c0 (LWP 197319)]
Press [q] to stop, [?] for help
[Thread 0x7fffeefea6c0 (LWP 197319) exited]
[mjpeg @ 0x519000002d80] not enough bytes remaining in EXIF buffer. entries: 16752
[mjpeg @ 0x519000002d80] overread 8
[mjpeg @ 0x519000002d80] EOI missing, emulating

Thread 4 "dec0:0:mjpeg" received signal SIGSEGV, Segmentation fault.
```

Even without context, these lines are interesting:

```text
[mjpeg @ 0x519000001480] not enough bytes remaining in EXIF buffer. entries: 16752
[mjpeg @ 0x519000002d80] not enough bytes remaining in EXIF buffer. entries: 16752
[mjpeg @ 0x519000002d80] overread 8
[mjpeg @ 0x519000002d80] EOI missing, emulating
```

A reasonable early hypothesis: something went wrong while parsing EXIF, and we ended up with corrupted metadata / invalid pointers.

The crash line also gives a useful hint:

```text
Thread 4 "dec0:0:mjpeg" received signal SIGSEGV, Segmentation fault.
```

The thread name (`dec0:0:mjpeg`) suggests the crash happens in the MJPEG decode path.

---

## Getting close: the last call before the crash

Pwndbg can show source + assembly. Use:

* `layout next` (show code + asm)
* `r` (restart)
* `next` (step over)

Step until you reach `ffmpeg.c:1010`, where you see:

```c
ret = transcode(sch);
```

If you hit `next` once more, the program crashes. Great — we found the last call before the crash.

Restart again and set a breakpoint just before it:

```bash
$ start "-i bug_triggering_file -f null -"
$ break ffmpeg.c:1010
Breakpoint 3 at 0x555555fa5407: file fftools/ffmpeg.c, line 1010.
$ c
```

Now `next` triggers the crash reliably.

---

## Use a backtrace to locate the decoding path

When the program calls functions, the runtime stores information about each call (return address, locals, arguments, etc.) in a **stack frame**. Stack frames live in the **call stack**.

A **backtrace** tells you how execution reached the current location:

```bash
pwndbg> bt
```

Example:

```text
#0  0x0000555555de1636 in __asan::Allocator::Deallocate
#1  0x0000555555e79e50 in __interceptor_free ()
#2  0x0000555557874739 in exif_free_entry (entry=0x51a0000106e0) at libavcodec/exif.c:605
#3  av_exif_free (ifd=0x5150000303d8) at libavcodec/exif.c:620
#4  0x00005555578746fb in exif_free_entry (entry=0x5150000303c0) at libavcodec/exif.c:603
#5  av_exif_free (ifd=ifd@entry=0x50900000ff00) at libavcodec/exif.c:620
#6  0x00005555576a37c5 in exif_attach_ifd (...) at libavcodec/decode.c:2405
#7  0x00005555576a3001 in ff_decode_exif_attach_ifd at libavcodec/decode.c:2413
#8  0x0000555557e3ce7b in ff_mjpeg_decode_frame_from_buf (...) at libavcodec/mjpegdec.c:2860
#9  0x000055555769170c in decode_simple_internal (...) at libavcodec/decode.c:440
...
```

Frame `#8` stands out:

```text
#8  ... ff_mjpeg_decode_frame_from_buf (...) at libavcodec/mjpegdec.c:2860
```

Let’s jump to that frame:

```bash
pwndbg> frame 8
```

You land on:

```text
2860    ret = ff_decode_exif_attach_ifd(avctx, frame, &s->exif_metadata);
```

Check a few relevant values:

```bash
pwndbg> print buf
$2 = (const uint8_t *) 0x522000000100 "377330377", <incomplete sequence 340>
pwndbg> print frame
$3 = (AVFrame *) 0x515000002ac0
pwndbg> print &s->exif_metadata
$4 = (AVExifMetadata *) 0x52100000f998
```

Nice: we now have a precise “interesting breakpoint” location.

---

## Break at mjpegdec.c:2860 and follow the EXIF path

Restart and break on that line:

```bash
$ start "-i bug_triggering_file -f null -"
$ break mjpegdec.c:2860
$ continue
```

You’ll stop at:

```text
► 2860  ret = ff_decode_exif_attach_ifd(avctx, frame, &s->exif_metadata);
```

Look at the wrapper:

```c
int ff_decode_exif_attach_ifd(AVCodecContext *avctx, AVFrame *frame, const AVExifMetadata *ifd)
{
    AVBufferRef *dummy = NULL;
    return exif_attach_ifd(avctx, frame, ifd, &dummy);
}
```

At this point you *can* step through, but in practice you’ll quickly hit a wall:

* ASAN instrumentation adds a lot of noisy frames
* the decode path includes loops and checks that make manual single-stepping painful

What we need is the **exact instruction right before the crash**, without manually replaying everything.

---

## Deterministic debugging with rr

That’s where **rr** shines.

* rr: [https://github.com/rr-debugger/rr](https://github.com/rr-debugger/rr)
* Extra reading: [https://fitzgen.com/2015/11/02/back-to-the-futurre.html](https://fitzgen.com/2015/11/02/back-to-the-futurre.html)

rr lets you **record** a run, then **replay** it with GDB commands — including **reverse execution**.

Record:

```bash
$ rr record ./ffmpeg -i bug_triggering_file -f null -
```

Replay:

```bash
$ rr replay
```

Run until crash:

```bash
(rr) continue
```

Now the magic: reverse-step from the crash back to the last valid instruction:

```bash
(rr) reverse-step
```

Also helpful:

* `layout next` to show source + asm

After reversing past ASAN noise, you land back in code that matters, around:

```c
void av_freep(void *arg){
    void *val;
    memcpy(&val, arg, sizeof(val));
    memcpy(arg, &(void *) { NULL }, sizeof(val));
    av_free(val);
}
```

Now inspect `val`:

```bash
(rr) print val
$1 = (void *) 0xbebebebebebebebe
```

That value is a classic “poison/uninitialized/freed” pattern. Stepping forward leads to:

```text
av_free (ptr=0xbebebebebebebebe) at libavutil/mem.c
```

So we’re about to free an invalid pointer.

Reverse a bit more: `av_freep()` is being called with `&entry->value.ptr`.

```bash
(rr) print &entry->value.ptr
$2 = (void **) 0x51a0000106f8
```

What is that field?

From `exif.h` (simplified):

```c
struct AVExifEntry {
  // ...
  union {
    // ...
    void *ptr;
  } value;
};
```

Now inspect the argument passed to `av_freep`:

```bash
(rr) print arg
$1 = (void *) 0x51a0000d06f8
(rr) print 0x51a0000d06f8
$2 = 89747637470968
```

### Root cause hypothesis

At this point, the failure mode is pretty clear:

* `av_freep()` expects `*arg` to contain a valid heap pointer (or `NULL`).
* It reads that pointer via `memcpy(&val, arg, sizeof(val))`
* Then it calls `av_free(val)` (ultimately `free(val)`)

But in our run, `entry->value.ptr` contains **garbage / poisoned data**, meaning earlier logic populated EXIF structures with an invalid pointer derived from attacker-controlled file contents (or from corrupted metadata state).

So when cleanup happens (`av_exif_free()` → `exif_free_entry()` → `av_freep(&entry->value.ptr)`), the code ends up freeing a non-heap pointer and crashes.

---

## Where does `entry` come from?

Reverse-step further to find where the entry is being freed. You land in:

```c
void av_exif_free(AVExifMetadata *ifd)
{
    if (!ifd)
        return;
    if (!ifd->entries) {
        ifd->count = 0;
        ifd->size = 0;
        return;
    }
    for (size_t i = 0; i < ifd->count; i++) {
        AVExifEntry *entry = &ifd->entries[i];
        exif_free_entry(entry);
    }
    av_freep(&ifd->entries);
    ifd->count = 0;
    ifd->size = 0;
}
```

So the `AVExifEntry` array is derived from `AVExifMetadata`. If the metadata object is already corrupted (bad count/entries, or unsanitized entry fields), the free path will happily walk and free invalid pointers.

---

## The fix

FFmpeg maintainers confirmed the issue and patched it in this commit:

* [https://github.com/FFmpeg/FFmpeg/commit/742b0d4675a977c0cf67c306df95b4ef9aff7e36](https://github.com/FFmpeg/FFmpeg/commit/742b0d4675a977c0cf67c306df95b4ef9aff7e36)
