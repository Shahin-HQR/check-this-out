# Write Primitive (Heap Overflow)

This directory contains the Proof of Concept (PoC) for the **Heap Buffer Overflow** (Write Primitive) vulnerability in OpenEXR (CVE-2023-5841).

## Content
- `exploit.exr`: A maliciously crafted Deep Scanline OpenEXR file with an excessive sample count (~16 million).
- `harness.c`: A C harness designed to bypass the standard library safety checks (`ImfCheckFile`) and trigger the vulnerable `generic_unpack_deep` function directly.

## Usage

### Quick Start (Pre-compiled)
We have included the vulnerable/instrumented libraries and the compiled harness.
Simply run the helper script:
```bash
./run_exploit.sh
```

### Manual Compilation
If you wish to compile from source:
1. **Compile the Harness:**
   Requires `libOpenEXR` (vulnerable versions <= 3.2.1) and `libOpenEXRCore`.
   ```bash
   clang -o harness harness.c -I/path/to/openexr/include -L/path/to/openexr/lib -lOpenEXRCore -lOpenEXR -lImath -lz
   ```

2. **Run the Exploit:**
   ```bash
   ./harness exploit.exr
   ```

## Expected Behavior
The process will crash with `SIGBUS` or `SIGSEGV` (Segmentation Fault).
- **Cause**: The library attempts to write ~64MB of data ('A's or 0s) to a small heap buffer, overflowing the check and eventually hitting the **Malloc Guard Page** or unmapped memory.
- **Impact**: Demonstrates the ability to overwrite heap memory.

## Note on iOS
This exploit typically triggers an immediate crash on iOS versions prior to 18.0 (e.g., iOS 17.3) due to memory protection mechanisms.
