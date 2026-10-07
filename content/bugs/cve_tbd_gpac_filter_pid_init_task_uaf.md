---
title: "CVE-2026-TBD - Use-after-free read in GPAC filter-session PID init task"
date: 2026-10-06T10:06:00+01:00
draft: false
description: ""
weight: -4
tags: ["bug"]
---

## Summary

- **CVE:** CVE-2026-TBD (CVE ID requested via MITRE, batch submission 2026-07-19)
- **Component:** `filter_pid.c` (filter-session core / PID resolution)
- **Vulnerability Type:** Use-after-free (8-byte pointer read)
- **Vendor:** GPAC
- **Product:** GPAC (libgpac / MP4Box / gpac)
- **Affected Versions:** master branch, commit `9bfcd13401cd1e52f966d03670c433d25952472c` (26.03-DEV)
- **Fix Status:** Fixed upstream: commit [`03e5b1c`](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e) (2026-07-22); [issue #3743](https://github.com/gpac/gpac/issues/3743) closed 2026-07-23
- **Severity:** Medium (5.5 / CVSS 3.1, 6.9 / CVSS 4.0): `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H`
- **Credit:** Salim Largo (2ourc3)

---

## Description

A heap use-after-free read exists in GPAC's filter-session core, in `gf_filter_pid_init_task()`. While resolving the filter chain for a newly-created PID, the task function can end up dereferencing a PID (or its owning filter) that was freed as part of that same resolution process.

---

## Root cause

`gf_filter_pid_init_task` (`src/filter_core/filter_pid.c:5612`):

```c
new_f = gf_filter_pid_resolve_link_check_loaded(pid, ...);  // may free `pid` / `pid->filter`
if (!new_f) {
    if (skipped) continue;
    if (pid->filter->session->run_status != GF_OK) { ... }  // 5612: use-after-free read
```

During link resolution, the PID or its owning filter is destroyed (via `gf_filter_swap_source_register` → `gf_fs_post_task` → `gf_fs_post_task_ex`, which frees it), but the init task keeps dereferencing `pid->filter->session`. This is a filter-graph lifetime bug likely sharing a root cause with [the self-destructing-filter UAF in `gf_filter_process_task`](/bugs/cve_tbd_gpac_filter_process_task_uaf/).

---

## Proof of Concept

```sh
afl-clang-fast -O1 -g -fsanitize=address -DGPAC_HAVE_CONFIG_H -I gpac_src -I gpac_src/include \
  harnesses/session_replay.c -L gpac_src/bin/gcc -lgpac -Wl,-rpath,gpac_src/bin/gcc -o session_replay
LD_LIBRARY_PATH=gpac_src/bin/gcc ./session_replay poc_file_uaf_read_filter_pid_init_task
```

Equivalent path: `gf_fs_new(0, GF_FS_SCHEDULER_DIRECT, GF_FS_FLAG_NO_REGULATION)` running `inspect:deep:analyze=on:allp` over the input registered as a `gmem://` blob. The `gpac` / `MP4Box` CLI does not trigger this directly.

### Observed ASan output (trimmed)

```text
==98690==ERROR: AddressSanitizer: heap-use-after-free on address 0x7c4e8a7e03c8
READ of size 8 at 0x7c4e8a7e03c8 thread T0
    #0 gf_filter_pid_init_task src/filter_core/filter_pid.c:5612:14
    #1 gf_fs_post_task_ex src/filter_core/filter_session.c:973:3
    #2 gf_filter_pid_post_init_task src/filter_core/filter_pid.c:6028:2
    ...

0x7c4e8a7e03c8 is located 8 bytes inside of 368-byte region
freed by thread T0 here:
    #0 free (asan interceptor)
    #1 gf_fs_post_task_ex src/filter_core/filter_session.c:973:3
    #2 gf_fs_post_task src/filter_core/filter_session.c:1096:2
    #3 gf_filter_swap_source_register src/filter_core/filter.c:4130:3
    #4 gf_filter_pid_resolve_link_internal src/filter_core/filter_pid.c:3875:11
    #5 gf_filter_pid_resolve_link_check_loaded src/filter_core/filter_pid.c:4187:9
    #6 gf_filter_pid_init_task src/filter_core/filter_pid.c:5605:12
    ...

SUMMARY: AddressSanitizer: heap-use-after-free src/filter_core/filter_pid.c:5612:14 in gf_filter_pid_init_task
```

---

## Fix

Fixed upstream in commit [`03e5b1c`](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e) (2026-07-22), titled *"fuzz: fix mem errors from filter setup_failure() and others"*, a single patch that closed all ten vulnerabilities reported in this batch.

Unlike the other nine bugs in the batch, this one isn't fixed by the deferred-teardown change; it's fixed directly in `gf_filter_pid_init_task()` (`src/filter_core/filter_pid.c`) by reordering the two early-exit checks. The `reassigned` check (PID already destroyed) now runs *before* the `pid->filter->session->run_status` check, so a reassigned PID is handled and the function returns before anything touches `pid->filter` again:

```c
//filter was reassigned (pid is destroyed), return
if (reassigned) {
    if (num_pass==1) {
        can_reassign_filter = GF_TRUE;
        continue;
    }
    gf_mx_v(filter->session->filters_mx);
    if (loaded_filters) gf_list_del(loaded_filters);
    gf_list_del(linked_dest_filters);
    gf_list_del(force_link_resolutions);
    gf_list_del(possible_linked_resolutions);
    return;
}

if (pid->filter->session->run_status!=GF_OK) {
    ...
```

Previously the `run_status` check (which dereferences `pid->filter`) ran first, so a PID that had just been destroyed via `reassigned` would still get dereferenced before the function had a chance to bail out.

---

## Impact

Use-after-free read in the filter-graph builder, reachable for untrusted input that forces filter re-resolution (observed via a chained `filelist`/HTTP source load). Denial of service and potential information disclosure (an 8-byte pointer read from freed heap memory).

---

## Timeline

| Date | Action |
|---|---|
| 2026-07-19 | Reported upstream ([issue #3743](https://github.com/gpac/gpac/issues/3743)) |
| 2026-07-21 | Session-replay harness shared with maintainer on request |
| 2026-07-22 | Fixed upstream, commit `03e5b1c` |
| 2026-07-23 | Issue closed |

---

## References

* **GitHub issue:** [gpac/gpac#3743](https://github.com/gpac/gpac/issues/3743) (closed)
* **Fix commit:** [03e5b1c23a52c2524d0f06f9909d56de5825292e](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e)
* **Discoverer:** Salim Largo (2ourc3), via fuzzing (AFL++ / libFuzzer + AddressSanitizer)
* **CVE status:** Requested from MITRE as part of a 10-vulnerability batch submission; CVE ID pending
