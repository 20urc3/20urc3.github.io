---
title: "Writing a fuzzer from scratch: Astra"
date: 2026-01-15T13:45:02+01:00
draft: false
weight: 1
---

![](header.png)  

Fuzzing is one of the rare automated vulnerability techniques that proved its efficiency for  the past decades. This article aims to explain how to design and write a modern unix-compatible fuzzer, comparable to [AFL++](https://github.com/AFLplusplus/AFLplusplus), [libFuzzer](https://llvm.org/docs/LibFuzzer.html) or [LibAFL](https://github.com/AFLplusplus/LibAFL), from scratch. It’s assumed the reader knows Rust and has a basic understanding of what a fuzzer is.

Today I'm releasing [Astra](https://github.com/20urc3/Astra), a Rust fuzzer made from scratch. This work wouldn’t have been possible without the excellent work of peers that published papers about novel approaches, developed, maintained and documented great open-source fuzzers. Open-source projects are often taken for granted, but in reality they exist because a small community is dedicating their time and efforts for everyone. Feel free to contribute in your way, resolve a `good first issue` on [AFL++](https://github.com/AFLplusplus/AFLplusplus) or [LibAFL](https://github.com/AFLplusplus/LibAFL), donate a coffee to the AFLplusplus organization, write documentation or simply use and share their work. 

A special thanks to the community of Awesome Fuzzing discord, and particularly to @eqv @tokka @vanhauser-thc @domenukk @addisson for answering my innumerable (sometimes silly) questions.

## Understanding fuzzer design: AFL.

Most modern fuzzers share common features: they execute a program under test, feed them mutated inputs and observe the result of their execution. The ideal beginning point to understand fuzzer design is to start by reading the [afl technical whitepaper](http://lcamtuf.coredump.cx/afl/technical_details.txt) and the [historical notes](https://github.com/google/AFL/blob/master/docs/historical_notes.txt). In these documents, the author describes their desire to make a fuzzer that will be: **fast**, **simple** to use, **reliable**, and **chainable**. 

Most of the features AFL offers are possible because of the coverage measurement, which allows to track branch (edge) coverage from the program under test, in this context this measurement is called a **trace**. The fuzzer maintains a global map of tuples seen in previous executions, which can be compared with an individual trace. When a mutated input produces an execution trace producing new tuples, it is preserved and routed for additional processing later on. 

Along with new tuples, the fuzzer also considers coarse tuple hit counts, divided into several buckets:  `1`, `2`, `3`, `4-7`, `8-15`, `16-31`, `32-127`, `128+`. Changes between the range of a single bucket are ignored while transitions from one bucket to another are flagged as interesting. The hit count behavior provides a way to distinguish between potentially interesting control flow changes, such as a block of code being executed twice when it was normally hit only once. 

Typically this monitoring of edges and hit counts accesses a coverage map that records these values. In AFL this coverage map is named `__afl_area_ptr`

The fuzzer enforces aggressive timeouts, roughly **5x** the initially-calibrated execution speed rounded to 20ms. This prevents dramatic fuzzer performance degradation by descending into tarpits that would not significantly improve the coverage while being **100x** slower.

Mutated test cases that produced new state transitions within the program are added to the input queue and used as a starting point for future rounds of mutation. They supplement but do not automatically replace existing finds. The progressive state exploration approach outlined above means that some of the test cases synthesized later on in the game may have edge coverage that is a strict superset of the coverage provided by their ancestors. 

To optimize the fuzzing effort, AFL periodically re-evaluates the queue using a fast algorithm that selects a smaller subset of test cases that still cover every tuple seen so far, and whose characteristics make them particularly favorable to the tool. This algorithm basically assigns a score for every entry based on multiple criterias such as: execution time, filesize. The **non-favorite** testcases are not disregarded completely, the odds of executing them is reduced to 1% if there is non-fuzzed favorite testcase left. Otherwise their execution chance grows to 5% if there is no new-favorite, and 25% for a non-favorite that has never been through a fuzzing round. This method is called by the author: **culling the corpus**. 

The testcase file size has a huge impact on the fuzzer performances, not only because it makes the program under test slower but it also reduces the chance to mutate an interesting part of the testcase rather than redundant data blocks. Aside from low-quality testcases, some mutations can iteratively increase the size of the testcases. The built-in trimmer attempts to sequentially remove blocks of data with variable length and stepover; any deletion that doesn't affect the checksum of the trace map is committed to disk. 

Along with the built-in trimmer, a standalone `afl-tmin` tool exists, it is using a more exhaustive and iterative algorithm and attempts to perform alphabet normalization on the trimmed files. Text normalization is the process of transforming text into a single canonical form that it might not have had before, think of: `madame curie` -> `radium came`.  
The tool will select the operating mode: 

1. If the testcase produces a crash it will keep any tweak that still produces the crash.  
2. If not, then it will run the instrumented program under test and keep only the tweaks that produce exactly the same execution path.

The fuzzing strategies, ergo which mutations are interesting or not, are detailed in the blogpost: [binary fuzzing strategies: what works, what doesn't](https://lcamtuf.blogspot.com/2014/08/binary-fuzzing-strategies-what-works.html). The feedback (code-coverage) provided by the instrumentation makes it easy to understand the value of various fuzzing strategies. AFL starts by a series of deterministic mutation strategies:

1. **Walking bit flips:** the first and most rudimentary strategy, it involves performing sequential, ordered bit flips. The stepover is always one bit, the number of bits flipped in a row varies from one to four. Across a large and diverse corpus of input files, the observed yields are:  
   1. Flipping a single bit: ~70 new paths per one million generated inputs
   2. Flipping two bits in a row: ~20 additional paths per million generated inputs
   3. Flipping four bits in a row: ~10 additional paths per million inputs. 

2. **Walking byte flips:** a natural extension of the walking bit flip approach, this method relies on `8-`, `16-`, or `32-bit` wide bitflips with a constant stepover of one byte.   
   1. This strategy discovers around ~30 additional paths per million inputs, on top of what could have been triggered with shorter bit flips. 

3. **Simple arithmetics:** to trigger more complex conditions in a deterministic fashion, the third stage attempts to subtly increment or decrement existing integer values in the input file, this is done with a stepover of one byte.

4. **Known integers**: the last deterministic approach employed by afl relies on a hardcoded set of integers chosen for their demonstrably elevated likelihood of triggering edge conditions in typical code (e.g., `-1`, `256`, `1024`, `MAX_INT-1`, `MAX_INT`). The fuzzer uses a stepover of one byte to sequentially overwrite existing data in the input file with one of the approximately two dozen "interesting" values, using both endians (the writes are `8`, `16`, and `32-bit` wide). 

5. **Stacked tweaks:** with deterministic strategies exhausted for a particular input file, the fuzzer continues with a never-ending loop of randomized operations that consist of a stacked sequence of:  
   1. Single-bit flips
   2. Attempts to set "interesting" bytes, words, or dwords (both endians)
   3. Addition or subtraction of small integers to bytes, words, or dwords (both endians)
   4. Completely random single-byte sets
   5. Block deletion
   6. Block duplication via overwrite or insertion
   7. Block memset

From the feedback obtained by the instrumentation it’s easy to identify syntax tokens, the detailed approach is detailed in the blogpost: [afl-fuzz: making up grammar with a dictionary in hand](https://lcamtuf.blogspot.com/2015/01/afl-fuzz-making-up-grammar-with.html). In essence mutation strategies are efficient for binary format but perform poorly when it comes to highly structured input such as text, messages or language. The algorithm can identify a syntax token by piggybacking on top of the deterministic, sequential bit flips that are already being performed across the entire file. 

It works by identifying runs of bytes that satisfy a simple property: that flipping them triggers an execution path that is distinct from the product of flipping stuff in the neighboring regions, yet consistent across the entire sequence of bytes. 

The fuzzer is attempting to de-dup crashes and consider a crash unique if any of two  
conditions are met:

- The crash trace includes a tuple not seen in any of the previous crashes.  
- The crash trace is missing a tuple that was always present in earlier faults.

AFL tries to address exploitability by providing a [crash exploration](https://lcamtuf.blogspot.com/2014/11/afl-fuzz-crash-exploration-mode.html) mode where a known-faulting test case is fuzzed in a manner very similar to the normal operation of the  
fuzzer, but with a constraint that causes any non-crashing mutations to be  
thrown away. Mutations that stop the crash from happening are thrown away, so are the ones that do not alter the execution path in any appreciable way. The occasional mutation that makes the crash happen in a subtly different way will be kept and used to seed subsequent fuzzing rounds later on. This mode very quickly produces a small corpus of related but somewhat different crashes that can be effortlessly compared to pretty accurately estimate the degree of control you have over the faulting address.

To improve performance AFL uses a "fork server" where the fuzzed process goes through execve(), linking, and libc initialization only once, and is then cloned from a stopped process image by leveraging copy-on-write. The implementation is described in more detail in the article: [fuzzing binaries without execve](http://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html).  It boils down to injecting a small piece of code into the fuzzed binary - a feat that can be achieved via *`LD_PRELOAD`*, via *`PTRACE_POKETEXT`*, via compile-time instrumentation, or simply by rewriting the ELF binary ahead of the time. The purpose of the injected shim is to let *`execve()`* happen, get past the linker (ideally with *`LD_BIND_NOW=1`*, so that all the hard work is done beforehand), and then stop early on in the actual program, before it gets to processing any inputs generated by the fuzzer or doing anything else of interest. In fact, in the simplest variant, we can simply stop at *`main()`*. 

The parallelization mechanism is periodically examining the queues produced by other local or remote instances, and selectively pulling the testcases that when tried out locally produced behaviors not yet seen by the fuzzer.

The binary only instrumentation mode relies on [QEMU](https://www.qemu.org/) in user-emulation mode, QEMU uses basic blocks as translation units; the instrumentation is implemented on top of this and uses a model roughly analogous to the compile-time hooks. The start-up of binary translators such as QEMU, DynamoRIO, and PIN is fairly slow. To counter this, the QEMU mode leverages a fork server similar to that used for compiler-instrumented code, effectively spawning copies of an already-initialized process paused at `_start`.

The afl-analyse tool is a format analyzer simple extension of the minimization algorithm  
discussed earlier on, instead of attempting to remove no-op blocks, the tool performs a series of walking byte flips and then annotates runs of bytes in the input file.

After reading the AFL technical specification, it appears that AFL is an out-of-process (meaning it spawns a child process) coverage-guided fuzzer. The big picture of AFL architecture can summarize as follow:

- The target under evaluation is compiled with a custom compiler that inserts instrumentation, then spawned as a child-process.  
- The testcases are mutated with deterministics then later random strategies.  
- The coverage (edge) is collected every fuzzing round, along with a block hit count.  
- Interesting testcases are kept in queue and prioritized for future fuzzing rounds.  
- Dictionaries are deduced from bytes that satisfy a simple property.  
- Crashes are classified as unique based on their tuples.  
- Exploitation exploration mode uses mutation to produce interesting similar testcases.  
- Parallelization is achieved through shared QUEUE with new testcases tuples.  
- Binary-only fuzzing relies on custom QEMU userland instrumentation.

Of course, dozens of other fuzzers exist and each have their own specificity, however, AFL laid out the way for modern fuzzers and we can find similar features in a lot of recent projects. A great way to learn more is to read the code of other state-of-the-art fuzzer such as [AFL++](https://github.com/AFLplusplus/AFLplusplus), [LibAFL](https://github.com/AFLplusplus/LibAFL), [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz), etc. 

## Designing a fuzzer architecture: Astra.

The main goal of Astra is to provide a **simple** to use and **reliable** fuzzer. For these reasons, and because it is objectively the best language in the world, this fuzzer will be written in Rust. It should be able to run on any UNIX distribution that supports Rust, provide a clear interface to the user and produce interesting results. The design is greatly inspired from AFL but for different reasons some choices differ from the old AFL version.

From the analysis of AFL architecture we can retain a few core concepts: corpus minimization, instrumentation - code-coverage, determinism, parallelization, mutation engine and fuzzing strategies, target observation and reporting. This constitutes a solid foundational design for the fuzzer, Astra is to be composed of multiple modules, each one designed to achieve a specific task.

- **CLI:** Command-line interface allowing the user to set some parameters to the fuzzer.  
- **Collector**: Collects corpus and transforms it into a memory-efficient collection.  
- **Instrumentation engine**: Transform the program under test into an observable target that returns coverage per execution.  
- **Monitor**: Monitor the state of the program under test after each run.  
- **Observer**: Observe the coverage achieved by each input fed to the program under test.  
- **Mutator**: Mutate inputs to achieve better coverage.  
- **Reporter**: Report the statistics gathered by the observer and the monitor.  
- **Runner**: Run the program under test and feed them a mutated input.

To understand a bit better how to design Astra, it is important to describe the workflow the fuzzer should follow to effectively stress a program under test.  The first step is to instrument our program under test in order to observe code-coverage feedback during its fuzz execution, this is achieved by AFL with a custom compiler that injects custom assembly in the program under test, Astra will skip this step and let the user directly instrument their target with `sancov`.  

The second step is to gather the corpus, the initial valid files we provide the fuzzer with, and transform them into mutable format, so that our third step, the mutation engine, can perform mutation on the testcases. The mutation engine will, based on deterministics or random approach, fuzz interesting (or not) testcases, the runner will then take a testcase candidate and run it against the target. After that the observer and the monitor will work in parallel to return precious information to the fuzzer: whether or not this testcases produced a crash OR interesting results.   

The graphical interface, in our case the TUI, will display these results to the user. This loops until the user decides to end the fuzzing campaign and voila! In summary, we can view the fuzzing process like this:  
```  
      Target instrumentation                       
                 |                                 
                 |                                 
                 v                                 
  Corpus collection and Transformation             
                 |                                 
                 |                                 
                 |                                 
                 v                                 
+-----------------------------------------------+  
|             Fuzzing LOOP                      |  
|                                               |  
| Mutation engine   |                           |  
|         ^         +--------->  Runner         |  
|         |                        |            |  
|         |                        |            |  
|         |                        |            |  
|         |                        v            |  
|         |                                     |  
|         +---------------------Observer        |  
|                                   |           |  
|                                   |           |  
|                                   |           |  
|              Reporter  <----------+           |  
|                                               |  
|                                               |  
+-----------------------------------------------+  
```

Astra needs to be compatible with Linux and Mac. The fuzzer logic is to be compiled into a static library, linked to the target program, that will feed inputs, monitor execution and perform reporting. 

To test the fuzzer during the development phase, I created several test programs: 

- A simple [nothing](https://github.com/20urc3/Astra/blob/main/PUTs/nothing.c) program that allow to test the performance bottlenecks of the fuzzer  
- A [reader](https://github.com/20urc3/Astra/blob/main/PUTs/reader.c) that reads a file from inputs and performs a few actions if some characters are detected.  
- A [parser](https://github.com/20urc3/Astra/blob/main/PUTs/parser.c) that reads and parses data from a file input. 

### Instrumentation Engine

Astra needs to collect code-coverage on Linux, Windows and MacOS, thankfully clang offers code-coverage instrumentation and is available on all of these platforms. The setup is somehow trivial, we simply need clang and some LLVM tools that you can install by following their [getting started guide](https://llvm.org/docs/GettingStarted.html). It offers multiple coverage instrumentation methods, like [source-code coverage](https://clang.llvm.org/docs/SourceBasedCodeCoverage.html) or a [gcov](https://gcc.gnu.org/onlinedocs/gcc/Gcov.html) compatible instrumentation. The interesting one is `edge-coverage` because it offers a very granular coverage metric, this feature is provided by [SanCov](https://clang.llvm.org/docs/SanitizerCoverage.html).  

`SanCov` inserts calls to user-defined functions on function, basic-block or edge levels. An edge represents basically a control transfer between a `basic block A` and a `basic block B`, themself being simply a straight-line code sequence with no branches `in` except to the `entry` and no branches `out` except at the `exit`. In other words, `edges` allows us to track the branches of our executed program under test, and returns which path has been traveled or not per execution.

The documentation specifies that with the flag `-fsanitize-coverage=trace-pc-guard` the compiler will insert  `__sanitizer_cov_trace_pc_guard(&guard_variable)`for each edge, and each edge will have its own `guard_variable (uint32_t)`. A guard can be seen as a unique ID for an object. A few other flags are available too but for the moment the most important information is that the functions `__sanitizer_cov_trace_pc_*` should be defined by the user. 

To understand how to implement the `__sanitizer_cov_trace_pc_guard` function, let’s have a look at the `SanCov` [example](https://clang.llvm.org/docs/SanitizerCoverage.html). We can implement our own version and try it against the [`simple_reader.c`](https://github.com/20urc3/Astra/blob/main/docs/writing_astra/coverage_example/simple_reader_example.c) example, first we need to create a [simple_pc_guard.c](https://github.com/20urc3/Astra/blob/main/docs/writing_astra/coverage_example/simple_pc_guard.c) file, then we need to compile our reader and link it against our `trace-pc-guard` binary. New coverage is obtained and their guard value displayed when a new edge is discovered. A simple rust binding [`simple_coverage_example.rs`](https://github.com/20urc3/Astra/blob/main/docs/writing_astra/coverage_example/small_coverage_example.rs) is possible too. 

The target binary has to be linked to the runtime library, since the goal is to have an easy-to-use fuzzer, it is better not to ask the user to link their target manually. For this reason this task has to be automated by astra_linker, its job will be to link the target binary to the runtime library that contains Astra custom `__sanitizer_cov_trace_guard` implementation.

One hacky way to achieve this is to take the user target program as a `PathBuf` from the CLI, transform it into a string and use it as an argument to spawn a process with `Command::new`.  After that we can add a simple `Command` spawn and give it the correct instructions. Cargo will compile the custom `sancov` implementation into a static library and link it to the user provided target.  

The way AFL tracked code coverage was rather trivial but efficient, it starts by assigning a random ID to the edge, then performing an exclusive or on `last_basicblock` and `current_basicblock` to obtain a pseudo-random edge id, that is incremented by one. Basically the idea is that it allows to track edge coverage with minimum collision with  a good performance.   
```c  
cur_location = <COMPILE_TIME_RANDOM>;  
shared_mem[cur_location ^ prev_location]++;  
prev_location = cur_location >> 1;  
```

The custom `sancov` implementation that allows to track edge-coverage is statistically linked to the user target binary, how does it write to the edge-map the fuzzer uses to collect coverage? Here comes in place the concepts of `shared_memory` and `mmap`.

[Wikipedia](https://en.wikipedia.org/wiki/Shared_memory) defines shared memory as:

> a memory that may be simultaneously accessed by multiple programs with an intent to provide communication among them or avoid redundant copies.

and the [AFL’s documentation](https://afl-1.readthedocs.io/en/latest/about_afl.html) states that:

> The `shared_mem[]` array is a 64 kB SHM region passed to the instrumented binary by the caller. Every byte set in the output map can be thought of as a hit for a particular (branch_src, branch_dst) tuple in the instrumented code.

Astra is an out-of-process fuzzer, thus it needs a way to communicate with the child processes. To communicate between processes we can use different means called IPC mechanisms, plethora of methods exist: pipes, sockets, shared file, shared memory. Having performance in mind, Astra will use shared memory, this is the fastest a process could share information to another one. To understand this mechanism I crafted a very simple example of a [reader](https://github.com/20urc3/Astra/blob/main/docs/writing_astra/understanding_shm/reader.c) and a [writer](https://github.com/20urc3/Astra/blob/main/docs/writing_astra/understanding_shm/reader.c) using `shm_open` and `mmap` to read and write directly to memory. You can run the example by using the command: `make run`. 

If you want to learn more about the POSIX shared memory standard, it is well documented here: [https://man7.org/linux/man-pages/man7/shm_overview.7.html](https://man7.org/linux/man-pages/man7/shm_overview.7.html).

The flow of creating a shared memory space can be described this way: we first use `shm_open` to create a shared memory region, then we use `ftruncate` to size it accordingly to our data, after that we use `mmap` to map the region to our internal representation, here it is `struct MyData *data`, from now on any operation performed on `data` struct will be written onto the shared memory data, once finished we `munmap` the map to detach from it, then `shm_unlink` to remove the shared memory region.  

Working with `libc` in Rust can be challenging, thankfully some crates provides good Rust bindings allowing us to leverage `shm` from rust such as the [rustix](https://github.com/bytecodealliance/rustix) crate, which provides efficient memory-safe and I/O-safe wrappers to POSIX-like, Unix-like, Linux, and Winsock syscall-like APIs, with configurable backends.  A rust example of a shared memory read and write using `rustix` can be found in the [rust_shm](https://github.com/20urc3/Astra/tree/main/docs/writing_astra/understanding_shm/rust_shm) folder. 

The function linux `shm_open` offers the possibility to create or to attach to an existing file, we can pass a flag that specifies if we want to create the file if it doesn’t exist or if we simply want to read or write from it, from there it’s rather trivial, we can create a file in the parent process with a specific name, then open it in the child process at startup. The rust crate `rust-ctor` offers an initialization capabilities to function using the macro `#[ctor]` which means the function will be run at process startup. Note that we could also use `__sanitizer_cov_trace_pc_guard_init` to call the initialization of the shared memory. 

We define a `static mut` pointer that will hold the returned `ptr` from `mmap()`, and assign it `mmap()` returned value. It’s important to define a size for our map, we will use the maximum size a 64-bits integer can hold in rust `262_144` by declaring a `const MAP_SIZE: usize = 262_144`. This value is to be used to truncate the shared memory file by `ftruncate` which takes a `u64` as input. The edge map will follow the same design old AFL did, except a little specificity here is that we need to create a slice from raw parts using the shared memory pointer and the size of the map, which forms a mutable slice from a pointer and a length. 

AFL design specifies tracking the edge hitcount, in other words  “how many times the same edge has been seen” and then it classifies them in different buckets. The bucketization groups the following hitcount: `0`, `1`, `2`, `3`, `4`, `8`, `16`, `32`, `128+`. Any transition from one bucket to another will be flagged as interesting. 

To determine if an input is interesting, the edge map obtained by a process is compared to a global map, this global map lives in the parent process and grows every time a new hitcount or new edge is discovered.

You can play with this early version of Astra by running the command:  `$ git checkout 1b38cb98f7901e7857f673c739b6cc1f4ec4251`then run the project against a binary instrumented with `trace-pc-guard`.  

### Corpus Collector

The corpus is the collection of initial testcase the user provides to the fuzzer; it is to be transformed into a format that allows the testcase to be mutated. Since the fuzzer goal is to be run in parallel mode, the corpus will be shared by different mechanisms, for that reason we use an atomic reference vector of vector of bytes to represent it `Arc<Vec<Vec<u8>>>`. The `input_dir` entry is added to the CLI and the corpus is collected in the main process.
```rust
use libc::c_void;
use rustix::{
    fs::{Mode, ftruncate},
    mm::{MapFlags, ProtFlags, mmap},
    shm,
};
use std::ptr::null_mut;

// Shared memory pointer
static mut SHM_PTR: *mut c_void = std::ptr::null_mut();

// Constant map size for the edge map
const MAP_SIZE: usize = 262_144;

/// This initiliziation function is *supposedly* ran only once per DSO
/// It opens the shared memory file only if it exist
/// Then map it to a global variable SHM_PTR used to write the coverage
#[unsafe(no_mangle)]
pub extern "C" fn __sanitizer_cov_trace_pc_guard_init(mut start: *mut u32, stop: *mut u32) -> () {
    // If not running under the fuzzer (e.g. during ./configure) just NO-OP.
    let shm_name = match std::env::var("ASTRA_SHM_ID") {
        Ok(s) => s,
        Err(_) => return,
    };

    // Open existing shared memory created by worker
    let fd = shm::open(&shm_name, shm::OFlags::RDWR, Mode::RUSR | Mode::WUSR).unwrap();

    let ptr: *mut c_void = unsafe {
        mmap(
            null_mut(),
            MAP_SIZE,
            ProtFlags::READ | ProtFlags::WRITE,
            MapFlags::SHARED,
            &fd,
            0,
        )
        .unwrap()
    };

    ftruncate(&fd, MAP_SIZE as u64).unwrap();

    // Assigning the mmaped `ptr` to SHM_PTR global variable
    unsafe {
        SHM_PTR = ptr;
    }

    // We always start at 1
    static mut N: u32 = 1;
    // Assert that the edge map isn't bigger than the shared memory.
    if (unsafe { stop.offset_from(start) }) > MAP_SIZE.try_into().unwrap() {
        return;
    };
    unsafe {
        if start == stop || *start != 0 {
            return;
        }
    };
    while start < stop {
        unsafe {
            *start = N;
            N += 1;
            start = start.add(1);
        }
    }
}

/// This function is called every time an edge is seen
/// It tracks edge coverage by assigninga unique ID per edge
/// and keeps count of the number of time an edge is seen.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) -> () {
    // If no shared memory mapped (e.g. ./configure),nm -a binutils/objdump | grep sanitizer just return.
    if SHM_PTR.is_null() {
        return;
    }

    let edge_map: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(SHM_PTR as *mut u8, MAP_SIZE) };
    let idx = unsafe { (*guard as usize) % MAP_SIZE };
    edge_map[idx] = edge_map[idx].wrapping_add(1);
}
```

### Observer

The observer part is responsible to determine if an input is interesting or not, as we saw earlier we can simply classify input as interesting by answering the questions: *have we discovered a new edge ? Has the edge hitcount bucket increased ?* A structure `CoverageFlags` holds two boolean values that are used as flags for this mechanism, the corresponding code is in `astra_observer/src/coverage.rs`.  You can check an initial version at: `eec07ed9b59ec7c89cfaa542c69dd9b631f6836a`

```rust
pub fn copy_map(dest_map: &mut Vec<u8>, src_map: &[u8]) {
    dest_map
        .iter_mut()
        .zip(src_map.iter())
        .for_each(|(dest, &src)| {
            *dest = (*dest).max(src);
        });
}

pub fn print_map(map: &[u8]) {
    for (idx, &edge_count) in map.iter().enumerate() {
        if edge_count != 0 {
            println!("map[{}] = {}", idx, edge_count);
        }
    }
}

// AFL-style bucket lookup table
pub fn bucketize(hit_count: u8) -> u8 {
    const BUCKETS: [u8; 256] = [
        0, 1, 2, 3, 4, 4, 4, 4, 8, 8, 8, 8, 8, 8, 8, 8, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
        16, 16, 16, 16, 16, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 128,
    ];
    BUCKETS[hit_count as usize]
}

pub struct CoverageFlags {
    pub new_edge: bool,
    pub new_hit: bool,
}

/// Compare two maps and returns flag i
/// if the next map is different than the previous one
pub fn compare_maps(previous_map: &Vec<u8>, new_map: &Vec<u8>) -> CoverageFlags {
    let mut flags = CoverageFlags {
        new_edge: false,
        new_hit: false,
    };

    for (idx, &prev_hit) in previous_map.iter().enumerate() {
        let new_hit = new_map[idx];

        if prev_hit == 0 && new_hit > 0 {
            flags.new_edge = true;
        }

        let prev_bucket = bucketize(prev_hit);
        let next_bucket = bucketize(new_hit);

        if prev_bucket < next_bucket {
            flags.new_hit = true;
        }

        if flags.new_edge && flags.new_hit {
            break;
        }
    }

    flags
}

pub fn count_raw_edges(map: &[u8]) -> usize {
    map.iter().filter(|&&x| x > 0).count()
}

pub fn total_raw_hits(map: &[u8]) -> usize {
    map.iter().map(|&x| x as usize).sum()
}
```

### Worker

The worker is the heart of the fuzzer, based on the number of CPU cores the user provides, the fuzzer will spawn the corresponding number of thread workers, each one mission is to feed a testcase from the corpus or the queue to the target, observe and report the result. 

Parallelism can be described as a method to execute multiple tasks at the same time on different cores, these tasks could be completely isolated or synced between cores. In old AFL, the fuzzer shared a corpus copy to each thread to avoid locking the shared `global_map` to other threads, then performed an update of the shared `global_map` only every now and then when new testcase are found. The writers have the priority to write into the shared `global_map` to avoid starvation, meaning other threads keep reading it and the writer can never write an input. The workers are run in a thread pool design, feeding inputs from the queue or the corpus.  If you want to read more about this you can read the excellent book: [Rust Atomics and Locks](https://marabos.nl/atomics/basics.html). 

Thankfully Rust offers more modern, fast and reliable mechanisms to do that. In Astra we will use the crate `crossbeam` and its channel to create a priority list of inputs that yielded interesting results in a previous run, a normal list of inputs collected from the corpus, a global map owned only by the main thread. Channels are used to pass data without having to share them amongst threads, which not only scales well but also prevents a lot of overhead from locks. You can check an initial version of `astra_worker/lib.rs` and `astra_worker/worker.rs` at this checkout: `ea65117f70123e325af9d1ac075e341de24f32cd`

```rust
//! This file provides function to spawn a worker.
//! A worker is thread that spawn the target program as a child-process
//!
//! Its arguments are:
//! - thread id
//! - A input to process
//! - A path to the target program
//!
//! - It establish a unique shared memory between the thread
//! and the child-process, used to share the edge_map
//! - It returns input and new edge-map to the main process

use astra_monitor::*;
use astra_mutator::*;
use astra_observer::shm::*;
use astra_scheduler::*;
use astra_tui::log_info;

use chrono;
use colored_text::Colorize;
use flume::{Receiver, Sender};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use wait_timeout::ChildExt;

const MAP_SIZE: usize = 262_144;

pub fn worker(
    id: u16,
    target: PathBuf,
    timeout: u64,
    args_before: Vec<String>,
    args_after: Vec<String>,
    corpus: InputQueue,
    send_cov: Sender<(u16, Vec<u8>, Vec<u8>)>,
    send_crash: Sender<bool>,
    send_hang: Sender<bool>,
) {
    // Initialize findings/hangs holder and shared memory
    let mut finding = false;
    let mut hang = false;
    log_info!("Astra-worker", "The worker {id} has started");
    let timeout_ms = std::time::Duration::from_millis(timeout);
    let mut local_map = vec![0u8; MAP_SIZE];
    let (_, ptr, shm_id) = create_shared_memory(id);
    let edge_map = unsafe { std::slice::from_raw_parts_mut(ptr as *mut u8, MAP_SIZE) };

    loop {
        let Some(mut input) = corpus.get_next() else {
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        };

        random_havoc(&mut input);
        edge_map.fill(0);

        let tmp = std::env::temp_dir().join(format!("input_{id}.tmp"));
        std::fs::write(&tmp, &input).unwrap();
        let mut cmd_args = args_before.clone();
        cmd_args.push(tmp.to_string_lossy().to_string());
        cmd_args.extend(args_after.clone());

        let mut child = Command::new(&target)
            .args(&cmd_args)
            .env("ASTRA_SHM_ID", &shm_id)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to run the target");

        match child.wait_timeout(timeout_ms).unwrap() {
            Some(status) => match status.signal() {
                Some(0) => {}
                Some(11) => {
                    record_crash(input.clone());
                    finding = true;
                    let _ = send_crash.send(finding);
                }
                _ => {}
            },

            None => {
                child.kill().unwrap();
                hang = true;
                let _ = send_hang.send(hang);
                child.wait().unwrap();
            }
        };

        let local_copy = edge_map.to_vec();
        send_cov.send((id, input, local_copy)).unwrap();
    }
}
```

### Mutation Engine

Feeding inputs to a target is great but it’s important that the fuzzer mutates them in order to discover new edges. There are plenty of different kinds of mutations, on bits level, bytes level, or even segments. Some of them are inserting, replacing, swapping, deleting from the mutated input. More advanced mechanics exist such as splicing or even text normalization. Other mutators operate on highly structured input such as grammar mutator, which allows to produce syntactically correct inputs.

A good first start is to implement simple havoc mutation that will operate on one or multiple bytes, using AFL and LibAFL as inspiration. You can check the mutation engine at `astra_mutator/havoc_mutations` at this checkout: `233a5e3038da98c0127d544a1dc71463a8d344cf`. By running the fuzzer with a simple input containing the letter `b` it is now able to find all the branches of the small test program. 

```rust
//! This file provide havoc mutation in an AFL style
//!
//! The function tkaes 3 arguments:
//! - An input which is a vector of bytes
//! - The length of the input to avoid redundant computation
//! - The number of mutations

use rand::Rng;

/// Type alias for the function pointer signature
pub type MutatorFunction = fn(&mut Vec<u8>);

/// Flips a random bit in a random byte
pub fn bit_flip(input: &mut Vec<u8>) {
    let length = input.len() as u32;
    let mut rng = rand::rng();
    let byte_index = rng.random_range(0..length - 1) as usize;
    let bit_index = rng.random_range(0..8) as usize;
    input[byte_index] ^= 1 << bit_index;
}

/// Flips a random byte with another random byte
pub fn bytes_swap(input: &mut Vec<u8>) {
    let length = input.len() as u32;
    let mut rng = rand::rng();
    let previous_byte = rng.random_range(0..length - 1) as usize;
    let next_byte = rng.random_range(0..length - 1) as usize;
    input.swap(previous_byte, next_byte);
}

/// Inserts a random byte at random index
pub fn bytes_insert(input: &mut Vec<u8>) {
    let length = input.len() as u32;
    let mut rng = rand::rng();
    let byte_index = rng.random_range(0..length - 1) as usize;
    let random_byte: u8 = rng.random_range(0..=255);
    input.insert(byte_index, random_byte);
}

/// Deletes a random byte at a random index
/// To avoid producing too small test cases, the function check if the length is
/// superior to 23 bytes (arbitrary value)
pub fn bytes_delete(input: &mut Vec<u8>) {
    let length = input.len() as u32;
    if length > 23 {
        let mut rng = rand::rng();
        let byte_index = rng.random_range(0..length - 1) as usize;
        input.remove(byte_index);
    }
}

/// Increase a random byte at random index
pub fn bytes_inc(input: &mut Vec<u8>) {
    let length = input.len() as u32;
    let mut rng = rand::rng();
    let byte_index = rng.random_range(0..length - 1) as usize;
    input[byte_index] = input[byte_index].wrapping_add(1); // This allows to overflow if 255
}

/// Decrement a random byte at random index
pub fn bytes_dec(input: &mut Vec<u8>) {
    let length = input.len() as u32;
    let mut rng = rand::rng();
    let byte_index = rng.random_range(0..length - 1) as usize;
    input[byte_index] = input[byte_index].wrapping_sub(1); // This allows to underflow if 0
}

/// Negates a random byte at a random index
pub fn bytes_neg(input: &mut Vec<u8>) {
    let length = input.len() as u32;
    let mut rng = rand::rng();
    let byte_index = rng.random_range(0..length - 1) as usize;
    input[byte_index] = input[byte_index].wrapping_neg();
}

/// Randomized the value of a random byte at random index
pub fn bytes_rand(input: &mut Vec<u8>) {
    let length = input.len() as u32;
    let mut rng = rand::rng();
    let byte_index = rng.random_range(0..length - 1) as usize;
    input[byte_index] = rng.random_range(0..=255) as u8;
}

/// Copy a random byte at random index and insert it right after
pub fn bytes_copy(input: &mut Vec<u8>) {
    let length = input.len() as u32;
    let mut rng = rand::rng();
    let byte_index = rng.random_range(0..length - 1) as usize;
    let byte_copy = input[byte_index];
    input.insert(byte_index + 1, byte_copy);
}

/// Expand the input by a random byte for a number of mutations passed
pub fn bytes_expand(input: &mut Vec<u8>) {
    let length = input.len() as u32;
    if length < 10_000_000 {
        let mut rng = rand::rng();
        let random_byte = rng.random_range(0..=255) as u8;
        input.push(random_byte);
    }
}

/// Shrinks the input by a byte
pub fn byte_shrink(input: &mut Vec<u8>) {
    let length = input.len() as u32;
    if length > 23 {
        input.pop();
    }
}
```

### Monitor

This component collects termination signals of the program under test, we can simply observe the child process exit code, if the signal is not `0` this means some problem occurred. The fuzzer then saves the file with a unique hash based on the file content in the `output/crashes/` folder.   You can check the monitoring at `astra_monitor/lib.rs` at this checkout: `b33c868b8b7814b398171f332cd25dc866d3f08f`.

```rust
use std::fs;
use std::hash::Hash;
use std::io::prelude::*;

/// Saves crashing unique input to a crash folder
pub fn record_crash(input: Vec<u8>) {
    fs::create_dir_all("./output/crashes").unwrap();
    let unique_hash = sha256::digest(&input);
    let filename = format!("./output/crashes/crash_{}", unique_hash);
    let mut file = fs::File::create(filename).unwrap();
    file.write_all(&input).unwrap();
}
```

### Statistics

Astra isn’t super original, a good starting will be to cover these essentials metrics:

- Runtime  
- Last time since a new path has been found  
- Total path or hitcount found  
- Total crashes  
- Total execution  
- Execution speed

You can checkout the commit `8fb92493de6af1c55970bc4d7504a43916a83691` and look at the code at `astra_tui/lib.rs` and `astra_worker/lib.rs` / `astra_worker/worker.rs` if you are curious to see this initial implementation. 

```rust
pub mod worker;

use worker::*;

use astra_collector::collect_corpus;
use astra_observer::coverage::*;
use astra_scheduler::*;
use astra_tui::*;

const MAP_SIZE: usize = 262_144;

use chrono;
use colored_text::Colorize;
use flume::unbounded;
use std::sync::atomic::Ordering;
use std::{path::PathBuf, thread};

/// Creates and run the worker pool
pub fn running_workers(
    num_thr: u16,
    input_dir: PathBuf,
    timeout: u64,
    target: PathBuf,
    arguments: Vec<String>,
) {
    let (send_cov, recv_cov) = unbounded::<(u16, Vec<u8>, Vec<u8>)>();
    let (send_crash, recv_crash) = unbounded::<bool>();
    let (send_hang, recv_hang) = unbounded::<bool>();

    // Initial the corpus queues with user seeds
    let mut initial_corpus = collect_corpus(&input_dir);
    assert!(!initial_corpus.is_empty());
    let corpus = InputQueue::new();
    for input in initial_corpus {
        corpus.add_normal(input);
    }

    // Prepare map and statistics
    let mut global_map = vec![0u8; MAP_SIZE];
    let fuzz_stats = FuzzingStats::new();
    let start_time_instant = std::time::Instant::now();
    let mut last_print_time = std::time::Instant::now();
    let mut last_time_new_path = std::time::Instant::now();

    let (args_before, args_after): (Vec<String>, Vec<String>) = {
        if let Some(pos) = arguments.iter().position(|arg| arg == "@@") {
            (arguments[..pos].to_vec(), arguments[pos + 1..].to_vec())
        } else {
            (arguments.clone(), Vec::new())
        }
    };

    // Spawn the threads
    let mut worker_handles = Vec::new();
    for id in 0..num_thr {
        let corpus = corpus.clone();
        let send_cov = send_cov.clone();
        let send_crash = send_crash.clone();
        let send_hang = send_hang.clone();
        let target = target.clone();
        let args_before = args_before.clone();
        let args_after = args_after.clone();

        worker_handles.push(thread::spawn(move || {
            worker(
                id,
                target,
                timeout,
                args_before,
                args_after,
                corpus,
                send_cov,
                send_crash,
                send_hang,
            )
        }));
    }

    loop {
        while let Ok((_, input, child_map)) = recv_cov.try_recv() {
            let flags = compare_maps(&mut global_map, &child_map);

            if flags.new_edge || flags.new_hit {
                corpus.add_priority(input);
                fuzz_stats.tot_path.fetch_add(1, Ordering::Relaxed);
                last_time_new_path = std::time::Instant::now();
            } else {
                corpus.add_normal(input);
            }

            copy_map(&mut global_map, &child_map);
            fuzz_stats.tot_execution.fetch_add(1, Ordering::Relaxed);

            let elapsed_secs = start_time_instant.elapsed().as_secs();
            fuzz_stats.run_time.store(elapsed_secs, Ordering::Relaxed);

            let tot_exec = fuzz_stats.tot_execution.load(Ordering::Relaxed);
            let exec_speed = if elapsed_secs > 0 {
                tot_exec / elapsed_secs
            } else {
                0
            };
            fuzz_stats.exec_speed.store(exec_speed, Ordering::Relaxed);

            let t_since_last = last_time_new_path.elapsed().as_secs();
            fuzz_stats
                .t_since_last_path
                .store(t_since_last, Ordering::Relaxed);

            fuzz_stats
                .raw_edges
                .store(count_raw_edges(&global_map), Ordering::Relaxed);
            fuzz_stats
                .raw_hits
                .store(total_raw_hits(&global_map), Ordering::Relaxed);
        }

        while let Ok(_) = recv_crash.try_recv() {
            fuzz_stats.tot_crash.fetch_add(1, Ordering::Relaxed);
        }

        while let Ok(_) = recv_hang.try_recv() {
            fuzz_stats.tot_tmout.fetch_add(1, Ordering::Relaxed);
        }

        if last_print_time.elapsed() >= std::time::Duration::new(1, 0) {
            let runtime = fuzz_stats
                .run_time
                .load(std::sync::atomic::Ordering::Relaxed);
            let t_since_last_path = fuzz_stats
                .t_since_last_path
                .load(std::sync::atomic::Ordering::Relaxed);
            let tot_path = fuzz_stats
                .tot_path
                .load(std::sync::atomic::Ordering::Relaxed);
            let raw_edges = fuzz_stats
                .raw_edges
                .load(std::sync::atomic::Ordering::Relaxed);
            let raw_hits = fuzz_stats
                .raw_hits
                .load(std::sync::atomic::Ordering::Relaxed);
            let tot_crash = fuzz_stats
                .tot_crash
                .load(std::sync::atomic::Ordering::Relaxed);
            let tot_tmout = fuzz_stats
                .tot_tmout
                .load(std::sync::atomic::Ordering::Relaxed);
            let tot_execution = fuzz_stats
                .tot_execution
                .load(std::sync::atomic::Ordering::Relaxed);
            let exec_speed = fuzz_stats
                .exec_speed
                .load(std::sync::atomic::Ordering::Relaxed);

            log_info!(
                "Astra-worker",
                "runtime: {} secs | time since last find: {} | total findings: {} | tot edges/hit: {}/{} | crash/timeout: {}/{}  | total exec: {} | exec/sec: {}",
                runtime,
                t_since_last_path,
                tot_path,
                raw_edges,
                raw_hits,
                tot_crash,
                tot_tmout,
                tot_execution,
                exec_speed
            );

            last_print_time = std::time::Instant::now();
        }
    }
}
```

### Installer

In a real-world scenario the user will desire to use the fuzzer against existing software that probably uses compiling systems such as Makefile, Just, Ninja, and so on. For this purpose it’s very convenient to have the static library `libastra_sancov.a` on the user’s system. 

The first step is to actually distribute Astra and its components properly to the host system, there are plenty of interesting but rather complex projects to do that in Rust such as `dist` (formerly `cargo-dist`), `cargo-bundle` and so on. For simplicity, we’ll use a good ol’ bash script that, when executed, will compile the project, save the static library `libastra_sancov.so` in the right folder and install the `astra` package on the system.  You can check this script at this commit: `8ab0255d3b9f96dcfa9325ad9220253a207f6d24` in this file: `utils/install.sh`.  

It is now possible to instrument any target with the following command: `CC=clang CFLAGS=” -fsanitize-coverage=trace-pc-guard -fsanitize=address” LD=clang LDFLAGS=”-lastra_sancov -fsanitize=address`. 

```bash
#!/bin/bash

# If no argument is provided, run cargo build and call this script again
if [ -z "$1" ]; then
    echo "Building project in release mode..."
    cargo build --release || { echo "Build failed"; exit 1; }

    # Find libsancov.a
    LIB_PATH=$(find target/release -name "libastra_sancov.a" | head -n 1)

    if [ -z "$LIB_PATH" ]; then
        echo "libsancov.a not found"
        exit 1
    fi

    echo "Re-running installer with library path: $LIB_PATH"
    exec "$0" "$LIB_PATH"
fi

# installer logic
LIBRARY_PATH=$1

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    INSTALL_PATH="/usr/local/lib"
    echo "macOS detected, installing to $INSTALL_PATH"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    INSTALL_PATH="/usr/lib"
    echo "Linux detected, installing to $INSTALL_PATH"
else
    echo "Unsupported OS"
    exit 1
fi

# Copy the library
sudo cp "$LIBRARY_PATH" "$INSTALL_PATH" && echo "Library installed successfully!" || {
    echo "Failed to install library"
    exit 1
}

# refreshing ldconfig
sudo ldconfig || {
    echo "Failed to refresh LDCONFIG"
    exit1
}

# Install binaries
cargo install --path crates/astra_fuzz || {
    echo "Failed to install astra binary"
    exit 1
}

cargo install --path crates/astra_cc || {
    echo "Failed to install astra_cc"
    exit1
}

cargo install --path crates/astra_cxx || {
    echo "Failed to install astra_cxx"
    exit1
}

echo "Astra and dependencies are installed successfully!"
```
### Making a `cc` and `cxx` wrapper

AFL and others offer a compiler wrapper so that users don't have to pass flags themself, this is exactly what astra do too. It ships with two compilers `astra_cc` and `astra_cxx` that can be used with building scripts such as `Makefile` and others. You can check these wrappers at this commit: `dc52a1c01d326074e27cf81df195d724ff42238a` in these files: `astra_cc/src/lib.rs` and `astra_cxx/src/lib.rs`. **Note**: We do not need a linker in the fuzzer anymore since linking now happens at compile time.

To test these wrappers I used `astra_cc` against the tool [htmldoc](https://github.com/michaelrsweet/htmldoc) with: `CC=astra_cc CXX=astra_cc LD=astra_cc ./configure && make -j(nproc)` and run Astra against an instrumented version of `htmldoc`.

```rust
use std::env;
use std::process::{Command, exit};

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();
    let is_compilation = args.contains(&"-c".to_string());

    if is_compilation {
        args.push("-fsanitize-coverage=trace-pc-guard".into());
        args.push("-fsanitize=address".into());
    } else {
        args.push("-fsanitize-coverage=trace-pc-guard".into());
        args.push("-fsanitize=address".into());
        args.push("-Wl,--whole-archive,--allow-multiple-definition".into());
        args.push("/usr/lib/libastra_sancov.a".into());
        args.push("-Wl,--no-whole-archive".into());
    }

    let status = Command::new("clang-20")
        .args(args)
        .status()
        .expect("failed to compile!");

    exit(status.code().unwrap_or(1));
}
```

The fuzzer is now good enough for a first run! 

![](image1.png)  

 We are now fuzzing an instrument binary with **our own custom coverage!** hoora!

### Accepting trailing arguments and improving the CLI

AFL doesn’t specify arguments itself, it receives it from the user and injects the filename at the position the user specified `@@`. For this reason we are going to implement a way to catch trailing arguments, read arguments after `--`, and inject the filename accordingly. It’s also a good time to improve the CLI more generally.  
Clap offers a good way to catch trailing arguments, basically anything that is after `--` will be stored in a `Vec<String>`, we can then simply iterate over the vector, catch the `@@` symbol and inject the filename at the right place. A simple version can be found in the file `astra/src/main.rs` and `astra_cli/src/lib.rs` at this checkout: `dc52a1c01d326074e27cf81df195d724ff42238a`. 

```rust
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about, long_about, trailing_var_arg = true)]
pub struct Args {
    #[arg(
        short = 'i',
        long = "input",
        help = "Specify the input folder path containing initial testcases."
    )]
    pub input_folder: PathBuf,

    #[arg(
        short = 'o',
        long = "output",
        default_value = "output",
        help = "Specify the output folder where crashing or hanging inputs are saved."
    )]
    pub output_folder: PathBuf,

    #[arg(
        short = 't',
        long = "timeout",
        default_value = "5000",
        help = "Specify the number of ms before considering the target program has timeout."
    )]
    pub timeout: u64,

    #[arg(
        short = 'c',
        long = "cores",
        default_value = "4",
        help = "Specify the number of core used for parallel fuzzing."
    )]
    pub cores: u16,

    #[arg(short = 'p', long = "program", help = "Specify the program to fuzz.")]
    pub program: PathBuf,

    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        help = "Specify the arguments passed to the target program."
    )]
    pub arguments: Vec<String>,
}
```

### Catching timeouts

Some bug classes do not result in an immediate crash but in a hang of the target program, for example a function could expect an argument to never be greater than a certain size, but not enforce any verification, which could result in infinite loop. It’s important to catch these errors too without flooding the user with false positives, for that reason the default value of a timeout is quite high and it’s up to the user to adjust it accordingly. 

Writing a timeout catcher can be complex because we have to deal with signal handling and of specific cases, thankfully there is the [crate wait_timeout](https://github.com/alexcrichton/wait-timeout) that already provides a handy `wait_timeout()` function. Of course we need some small adaptations in the worker to return the results, crash or hangs, to the main thread. If we set the CLI default with a timeout of 10ms we can see it catches errors properly:  

![](image2.png)

You can find an example at `astra_worker/src/worker.rs` at this checkout: `9c05b4f5ef2e3adfba21d094ee347f92a7a5645f` 

>**Note:** the timeout is defaulted to 10ms in the CLI in this example.

Voila! Astra is now essentially a rudimentary but complete fuzzer!

## Conclusion


Astra shows that building a modern fuzzer isn’t magic: it’s a set of simple mechanisms engineered carefully. By combining fast coverage feedback, a shared map, a basic corpus loop, and aggressive mutations, we already get something surprisingly effective and scalable. This project is intentionally educational, so there’s still a lot to improve: scheduling, minimization, and deeper heuristics, but the foundation is solid. 

If you want to truly understand fuzzing, **writing one is the fastest path.**
