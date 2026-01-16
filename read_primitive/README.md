# Read Primitive (Out-Of-Bounds Read)

This directory contains the Proof of Concept (PoC) for the **Out-Of-Bounds Read** (Read Primitive) aspect of CVE-2023-5841.

## Content
- `exploit.exr`: A malicious OpenEXR file designed to cause the library to read past the end of the input buffer.
- `harness.c`: The same harness used for the write primitive.

## Usage

### Quick Start (Pre-compiled)
We have included the vulnerable/instrumented libraries and the compiled harness.
Simply run the helper script:
```bash
./run_exploit.sh
```
*Note: The included library is instrumented to print "LEAK: ..." during the operation.*

### Manual Compilation
If you wish to compile from source:
1. **Compile the Harness:**
   (Same as Write Primitive)

2. **Instrument the Library (Optional but Recommended):**
   To visualize the leak, it is recommended to add a `printf` statement inside the `UNPACK_SAMPLES` macro in `unpack.c` (within `libOpenEXRCore`) to print the values being read from `src`.

3. **Run the Exploit:**
   ```bash
   ./harness exploit.exr
   ```
   
## Expected Behavior
- **With Standard Library**: The process will likely crash (`SIGBUS`) when the read pointer hits unmapped memory.
- **With Instrumented Library**: The output will show a stream of data read from consecutive heap addresses, demonstrating that the process creates a "Leaking" primitive before crashing.

## Impact
This primitive proves the ability to read ~4MB of adjacent heap memory, which could potentially expose sensitive data present in the process memory.
