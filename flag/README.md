# Flag Capture Exploit (Control Flow Hijacking)

This directory demonstrates **Arbitrary Code Execution (Control Flow Hijacking)** via the Heap Buffer Overflow.

## Overview
We simulate a precise heap overflow where the attacker has crafted the EXR file (or the library logic simulates it) to overwrite a specific function pointer on the heap.
1. The harness allocates a vulnerable buffer and a target victim struct (`UnsuspectingVictim`) immediately adjacent on the heap (Heap Grooming).
2. The `exploit.exr` triggers the overflow.
3. The overflow overwrites the `callback` function pointer in the victim struct.
4. The harness invokes the callback.
5. Execution is redirected to `flag1()`, printing the flag.

## Files
- `harness_flag.c`: The harness defining `flag1()` and the victim struct.
- `exploit.exr`: The malicious file (triggering the high-sample path).
- `run_exploit.sh`: Script to run the exploit with the vulnerable library.

## How it works
The `libOpenEXRCore` in `../libs_flag` has been modified to simulate the effects of a "perfectly crafted" malicious file that writes the address of `flag1` repeatedly over the heap chunk boundary. This bypasses the complexity of manually authoring an EXR file with specific 64-bit address payloads while maintaining valid chunk offsets (which requires deep file format parsing).

## Usage
```bash
./run_exploit.sh
```

## Expected Output
```text
[PWNED] CONTROL FLOW HIJACKED!
[FLAG]  CTF{H3ap_0verfl0w_2_C0d3_Ex3c_Succ3ss}
```
