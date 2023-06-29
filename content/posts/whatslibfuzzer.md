---
title: "LibFuzzer's Example"
date: "2023-06-29"
draft: "false"
---

## What is LibuFuzzer?
Libfuzzer is a library part of LLVM that can be used to fuzz test programs.

## Example
Build the fuzzing target.

```cpp
#include <stdint.h>
#include <stddef.h>

bool FuzzMe(const uint8_t *Data, size_t DataSize) {
  return DataSize >= 3 &&
    Data[0] == 'F' &&
    Data[1] == 'U' &&
    Data[2] == 'Z' &&
    Data[3] == 'Z';
}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzMe(Data, Size);
  return 0;
}
```

First, write `LLVMFuzzerTestOneInput` function.
This function is called by libfuzzer.
The function takes two arguments, `Data` and `Size`.
`Data` is the input data and `Size` is the size of the input data.

Next, build the fuzzing target.

```bash
clang++ -fsanitize=address,fuzzer fuzzme.cpp -o fuzzme
```

Finally, run the fuzzing target.

```bash
./fuzzme
```

Result

```bash
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3584568445
INFO: Loaded 1 modules   (7 inline 8-bit counters): 7 [0x56184dcaaed0, 0x56184dcaaed7), 
INFO: Loaded 1 PC tables (7 PCs): 7 [0x56184dcaaed8,0x56184dcaaf48), 
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2	INITED cov: 3 ft: 3 corp: 1/1b exec/s: 0 rss: 30Mb
#25	NEW    cov: 4 ft: 4 corp: 2/5b lim: 4 exec/s: 0 rss: 31Mb L: 4/4 MS: 3 CopyPart-ChangeBit-CMP- DE: "\377\377"-
#53	REDUCE cov: 4 ft: 4 corp: 2/4b lim: 4 exec/s: 0 rss: 31Mb L: 3/3 MS: 3 CrossOver-PersAutoDict-CrossOver- DE: "\377\377"-
#2933	NEW    cov: 5 ft: 5 corp: 3/9b lim: 29 exec/s: 0 rss: 31Mb L: 5/5 MS: 5 InsertByte-EraseBytes-ShuffleBytes-ChangeByte-CMP- DE: "F\000\000\000"-
#2970	REDUCE cov: 5 ft: 5 corp: 3/7b lim: 29 exec/s: 0 rss: 31Mb L: 3/3 MS: 2 PersAutoDict-EraseBytes- DE: "F\000\000\000"-
#63511	REDUCE cov: 6 ft: 6 corp: 4/10b lim: 625 exec/s: 0 rss: 35Mb L: 3/3 MS: 1 ChangeByte-
=================================================================
==15873==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000320ef3 at pc 0x56184dc67f3c bp 0x7ffd48006be0 sp 0x7ffd48006bd8
READ of size 1 at 0x602000320ef3 thread T0
    #0 0x56184dc67f3b in FuzzMe(unsigned char const*, unsigned long) (/home/user/fuzzing/tmp/fuzzme+0x117f3b) (BuildId: c836932b051a581aa53e493792e0a9dd92de2264)
    #1 0x56184dc67fd4 in LLVMFuzzerTestOneInput (/home/user/fuzzing/tmp/fuzzme+0x117fd4) (BuildId: c836932b051a581aa53e493792e0a9dd92de2264)
    #2 0x56184db8e323 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/home/user/fuzzing/tmp/fuzzme+0x3e323) (BuildId: c836932b051a581aa53e493792e0a9dd92de2264)
    #3 0x56184db8da79 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) (/home/user/fuzzing/tmp/fuzzme+0x3da79) (BuildId: c836932b051a581aa53e493792e0a9dd92de2264)
    #4 0x56184db8f269 in fuzzer::Fuzzer::MutateAndTestOne() (/home/user/fuzzing/tmp/fuzzme+0x3f269) (BuildId: c836932b051a581aa53e493792e0a9dd92de2264)
    #5 0x56184db8fde5 in fuzzer::Fuzzer::Loop(std::vector<fuzzer::SizedFile, std::allocator<fuzzer::SizedFile> >&) (/home/user/fuzzing/tmp/fuzzme+0x3fde5) (BuildId: c836932b051a581aa53e493792e0a9dd92de2264)
    #6 0x56184db7df22 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/home/user/fuzzing/tmp/fuzzme+0x2df22) (BuildId: c836932b051a581aa53e493792e0a9dd92de2264)
    #7 0x56184dba7c12 in main (/home/user/fuzzing/tmp/fuzzme+0x57c12) (BuildId: c836932b051a581aa53e493792e0a9dd92de2264)
    #8 0x7fa232229d8f in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #9 0x7fa232229e3f in __libc_start_main csu/../csu/libc-start.c:392:3
    #10 0x56184db72964 in _start (/home/user/fuzzing/tmp/fuzzme+0x22964) (BuildId: c836932b051a581aa53e493792e0a9dd92de2264)

0x602000320ef3 is located 0 bytes to the right of 3-byte region [0x602000320ef0,0x602000320ef3)
allocated by thread T0 here:
    #0 0x56184dc6585d in operator new[](unsigned long) (/home/user/fuzzing/tmp/fuzzme+0x11585d) (BuildId: c836932b051a581aa53e493792e0a9dd92de2264)
    #1 0x56184db8e232 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/home/user/fuzzing/tmp/fuzzme+0x3e232) (BuildId: c836932b051a581aa53e493792e0a9dd92de2264)
    #2 0x56184db8da79 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) (/home/user/fuzzing/tmp/fuzzme+0x3da79) (BuildId: c836932b051a581aa53e493792e0a9dd92de2264)
    #3 0x56184db8f269 in fuzzer::Fuzzer::MutateAndTestOne() (/home/user/fuzzing/tmp/fuzzme+0x3f269) (BuildId: c836932b051a581aa53e493792e0a9dd92de2264)
    #4 0x56184db8fde5 in fuzzer::Fuzzer::Loop(std::vector<fuzzer::SizedFile, std::allocator<fuzzer::SizedFile> >&) (/home/user/fuzzing/tmp/fuzzme+0x3fde5) (BuildId: c836932b051a581aa53e493792e0a9dd92de2264)
    #5 0x56184db7df22 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/home/user/fuzzing/tmp/fuzzme+0x2df22) (BuildId: c836932b051a581aa53e493792e0a9dd92de2264)
    #6 0x56184dba7c12 in main (/home/user/fuzzing/tmp/fuzzme+0x57c12) (BuildId: c836932b051a581aa53e493792e0a9dd92de2264)
    #7 0x7fa232229d8f in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16

SUMMARY: AddressSanitizer: heap-buffer-overflow (/home/user/fuzzing/tmp/fuzzme+0x117f3b) (BuildId: c836932b051a581aa53e493792e0a9dd92de2264) in FuzzMe(unsigned char const*, unsigned long)
Shadow bytes around the buggy address:
  0x0c048005c180: fa fa fd fa fa fa fd fa fa fa fd fa fa fa fd fa
  0x0c048005c190: fa fa fd fa fa fa fd fa fa fa fd fa fa fa fd fa
  0x0c048005c1a0: fa fa fd fa fa fa fd fa fa fa fd fa fa fa fd fd
  0x0c048005c1b0: fa fa fd fd fa fa fd fa fa fa fd fa fa fa fd fd
  0x0c048005c1c0: fa fa fd fd fa fa fd fd fa fa fd fa fa fa fd fa
=>0x0c048005c1d0: fa fa fd fa fa fa fd fa fa fa fd fa fa fa[03]fa
  0x0c048005c1e0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c048005c1f0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c048005c200: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c048005c210: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c048005c220: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==15873==ABORTING
MS: 1 ChangeByte-; base unit: a752bc62cd5e46579fc55a6b2c161ffe70cc20c1
0x46,0x55,0x5a,
FUZ
artifact_prefix='./'; Test unit written to ./crash-0eb8e4ed029b774d80f2b66408203801cb982a60
Base64: RlVa
```