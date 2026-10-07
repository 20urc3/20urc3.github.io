---
title: "CVE-2026-TBD - Heap buffer overflow in GPAC H.264/H.265 NALU reframer probe"
date: 2026-10-06T10:09:00+01:00
draft: false
description: ""
weight: -1
tags: ["bug"]
---

## Summary

- **CVE:** CVE-2026-TBD (CVE ID requested via MITRE, batch submission 2026-07-19)
- **Component:** `reframe_nalu.c` (H.264/H.265 NALU reframer format probe)
- **Vulnerability Type:** Heap buffer overflow (1-byte out-of-bounds read)
- **Vendor:** GPAC
- **Product:** GPAC (libgpac / MP4Box / gpac)
- **Affected Versions:** master branch, commit `9bfcd13401cd1e52f966d03670c433d25952472c` (26.03-DEV)
- **Fix Status:** Fixed upstream: commit [`03e5b1c`](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e) (2026-07-22); [issue #3742](https://github.com/gpac/gpac/issues/3742) closed 2026-07-23
- **Severity:** Medium (5.5 / CVSS 3.1, 5.1 / CVSS 4.0): `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H`
- **Credit:** Salim Largo (2ourc3)

---

## Description

A heap-buffer-overflow (1-byte out-of-bounds read) exists in GPAC's H.264/H.265 NALU reframer format probe: it reads `data[1]` without first checking that a second byte actually remains in the probe buffer.

---

## Root cause

`naludmx_probe_data` (`src/filters/reframe_nalu.c:4306`):

```c
if (data[0] & 0x40) { not_vvc++; continue; }
nal_type = data[1] >> 3;   // 4306: OOB read when only 1 byte remains
```

The probe walks NAL units across the buffer; when a single trailing byte remains, `data[1]` reads one byte past the end of the probe buffer, with no remaining-length check before the access.

---

## Proof of Concept

```sh
afl-clang-fast -O1 -g -fsanitize=address -DGPAC_HAVE_CONFIG_H -I gpac_src -I gpac_src/include \
  harnesses/session_replay.c -L gpac_src/bin/gcc -lgpac -Wl,-rpath,gpac_src/bin/gcc -o session_replay
LD_LIBRARY_PATH=gpac_src/bin/gcc ./session_replay poc_file_heap_bof_read_naludmx_probe
```

Equivalent path: `gf_fs_new(0, GF_FS_SCHEDULER_DIRECT, GF_FS_FLAG_NO_REGULATION)` running `inspect:deep:analyze=on:allp` over the input registered as a `gmem://` blob. The `gpac` / `MP4Box` CLI does not trigger this directly.

### Observed ASan output (trimmed)

```text
==98701==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7c4bc21e00b3
READ of size 1 at 0x7c4bc21e00b3 thread T0
    #0 naludmx_probe_data src/filters/reframe_nalu.c:4306:14
    #1 gf_filter_pid_raw_new src/filter_core/filter.c:4801:13
    #2 gf_filter_pid_raw_gmem src/filter_core/filter.c:4880:6
    ...

0x7c4bc21e00b3 is located 0 bytes after 51-byte region

SUMMARY: AddressSanitizer: heap-buffer-overflow src/filters/reframe_nalu.c:4306:14 in naludmx_probe_data
```

---

## Fix

Fixed upstream in commit [`03e5b1c`](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e) (2026-07-22), titled *"fuzz: fix mem errors from filter setup_failure() and others"*, a single patch that closed all ten vulnerabilities reported in this batch.

`naludmx_probe_data()` (`src/filters/reframe_nalu.c`) now guards the second-byte read with a remaining-length check:

```c
nal_type = size > 1 ? data[1] >> 3 : 0;
```

---

## Impact

Out-of-bounds heap read during format probing of untrusted H.264/H.265 input. Denial of service (crash).

---

## Timeline

| Date | Action |
|---|---|
| 2026-07-19 | Reported upstream ([issue #3742](https://github.com/gpac/gpac/issues/3742)) |
| 2026-07-21 | Session-replay harness shared with maintainer on request |
| 2026-07-22 | Fixed upstream, commit `03e5b1c` |
| 2026-07-23 | Issue closed |

---

## References

* **GitHub issue:** [gpac/gpac#3742](https://github.com/gpac/gpac/issues/3742) (closed)
* **Fix commit:** [03e5b1c23a52c2524d0f06f9909d56de5825292e](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e)
* **Discoverer:** Salim Largo (2ourc3), via fuzzing (AFL++ / libFuzzer + AddressSanitizer)
* **CVE status:** Requested from MITRE as part of a 10-vulnerability batch submission; CVE ID pending
