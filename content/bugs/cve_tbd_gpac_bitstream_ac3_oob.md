---
title: "CVE-2026-TBD - Heap buffer overflow in GPAC AC-3 bitstream reader"
date: 2026-10-06T10:07:00+01:00
draft: false
description: ""
weight: -3
tags: ["bug"]
---

## Summary

- **CVE:** CVE-2026-TBD (CVE ID requested via MITRE, batch submission 2026-07-19)
- **Component:** `bitstream.c` (core bitstream reader), reached via the AC-3 parser
- **Vulnerability Type:** Heap buffer overflow (1-byte out-of-bounds read)
- **Vendor:** GPAC
- **Product:** GPAC (libgpac / MP4Box / gpac)
- **Affected Versions:** master branch, commit `9bfcd13401cd1e52f966d03670c433d25952472c` (26.03-DEV)
- **Fix Status:** Fixed upstream: commit [`03e5b1c`](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e) (2026-07-22); [issue #3740](https://github.com/gpac/gpac/issues/3740) closed 2026-07-23
- **Severity:** Medium (5.5 / CVSS 3.1, 5.1 / CVSS 4.0): `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H`
- **Credit:** Salim Largo (2ourc3)

---

## Description

A heap-buffer-overflow (1-byte out-of-bounds read) exists in GPAC's core bitstream reader, reachable from the AC-3 audio parser: a bitstream declared larger than its backing allocation reads one byte past the end of that allocation.

---

## Root cause

`BS_ReadByte` (`src/utils/bitstream.c:460`), reached via `gf_bs_read_int` ← `gf_ac3_parser_bs` (`src/media_tools/av_parsers.c:10625`):

```c
if (bs->position >= bs->size) { ...; return 0; }
res = bs->original[bs->position++];   // 460: OOB read past the real allocation
```

The bounds check compares `position` against `bs->size`, but the AC-3 parse path builds a bitstream whose declared `size` exceeds the actually-allocated `bs->original` buffer. As a result, `position < size` passes the check while the byte read still lands past the real heap allocation.

---

## Proof of Concept

```sh
afl-clang-fast -O1 -g -fsanitize=address -DGPAC_HAVE_CONFIG_H -I gpac_src -I gpac_src/include \
  harnesses/session_replay.c -L gpac_src/bin/gcc -lgpac -Wl,-rpath,gpac_src/bin/gcc -o session_replay
LD_LIBRARY_PATH=gpac_src/bin/gcc ./session_replay poc_file_heap_bof_read_bitstream_ac3
```

Equivalent path: `gf_fs_new(0, GF_FS_SCHEDULER_DIRECT, GF_FS_FLAG_NO_REGULATION)` running `inspect:deep:analyze=on:allp` over the input registered as a `gmem://` blob. The `gpac` / `MP4Box` CLI does not trigger this directly.

### Observed ASan output (trimmed)

```text
==98712==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7c9f7f7e0396
READ of size 1 at 0x7c9f7f7e0396 thread T0
    #0 BS_ReadByte src/utils/bitstream.c:460:9
    #1 gf_bs_read_bit src/utils/bitstream.c:540:17
    #2 gf_bs_read_int src/utils/bitstream.c:572:10
    #3 gf_bs_read_int_log_idx3 src/media_tools/av_parsers.c:47:12
    #4 gf_ac3_parser_bs src/media_tools/av_parsers.c:10625:12
    #5 gf_ac3_parser src/media_tools/av_parsers.c:10599:8
    #6 ac3dmx_probe_data src/filters/reframe_ac3.c:577:9
    ...

0x7c9f7f7e0396 is located 0 bytes after 790-byte region

SUMMARY: AddressSanitizer: heap-buffer-overflow src/utils/bitstream.c:460:9 in BS_ReadByte
```

---

## Fix

Fixed upstream in commit [`03e5b1c`](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e) (2026-07-22), titled *"fuzz: fix mem errors from filter setup_failure() and others"*, a single patch that closed all ten vulnerabilities reported in this batch.

For this bug, `src/media_tools/av_parsers.c` was fixed in two places. First, `gf_ac3_parser()` now builds the bitstream with a size relative to the sync-code offset instead of the full original buffer length; this was the actual root cause, since it's what let the declared `size` exceed the real remaining allocation:

```c
bs = gf_bs_new((const char*)(buf + *pos), buflen-*pos, GF_BITSTREAM_READ);
```

Second, `gf_ac3_parser_bs()` gained an explicit length guard before reading the fixed-size AC-3 header fields:

```c
if (gf_bs_available(bs) < 6) {
    GF_LOG(GF_LOG_WARNING, GF_LOG_CODING, ("[AC3] Truncated buffer\n"));
    return GF_FALSE;
}
```

---

## Impact

Out-of-bounds heap read when parsing untrusted AC-3 audio streams. Denial of service (crash).

---

## Timeline

| Date | Action |
|---|---|
| 2026-07-19 | Reported upstream ([issue #3740](https://github.com/gpac/gpac/issues/3740)) |
| 2026-07-21 | Session-replay harness shared with maintainer on request |
| 2026-07-22 | Fixed upstream, commit `03e5b1c` |
| 2026-07-23 | Issue closed |

---

## References

* **GitHub issue:** [gpac/gpac#3740](https://github.com/gpac/gpac/issues/3740) (closed)
* **Fix commit:** [03e5b1c23a52c2524d0f06f9909d56de5825292e](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e)
* **Discoverer:** Salim Largo (2ourc3), via fuzzing (AFL++ / libFuzzer + AddressSanitizer)
* **CVE status:** Requested from MITRE as part of a 10-vulnerability batch submission; CVE ID pending
