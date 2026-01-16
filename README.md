# OpenEXR Heap Buffer Overflow Exploitation Package (CVE-2023-5841)

This package contains a comprehensive proof-of-concept suite for **CVE-2023-5841**, a critical heap buffer overflow vulnerability in OpenEXR (prior to v3.2.2). The suite demonstrates the vulnerability's impact ranging from a simple crash (DoS) to memory leaking, and finally to arbitrary code execution (Control Flow Hijacking).


> [!CAUTION]
> **DANGER: CRITICAL ZERO-DAY POTENTIAL**
> This vulnerability is extremely dangerous and can be used as a **0-day exploit** for any vulnerable device (iOS < 18.0). The provided exploits demonstrate how this bug can be weaponized for specific purposes, from Denial of Service to Arbitrary Code Execution.

```https://support.apple.com/en-us/121250```
## 📂 Directory Structure

| Folder | Purpose | Description |
| :--- | :--- | :--- |
| **`write_primitive/`** | **Heap Overflow (DoS)** | Demonstrates the uncontrolled write. Execution triggers a **SIGBUS/Crash** on the Malloc Guard Page. |
| **`read_primitive/`** | **OOB Read (Leak)** | Demonstrates out-of-bounds reading. Instrumented library prints leaked heap memory before crashing. |
| **`flag/`** | **Code Execution (RCE)** | Demonstrates **Control Flow Hijacking**. A custom harness grooms the heap, and the exploit redirects execution to a `flag1()` function. |
| `libs_write/` | Dependencies | Clean libraries for the write primitive. |
| `libs_read/` | Dependencies | Instrumented libraries for the read primitive. |
| `libs_flag/` | Dependencies | Exploitation-simulated libraries for the flag demo. |

---

## 🚀 Quick Start

Each primitive is self-contained. Navigate to the folder and run the script:

### 1. Crash Demo (Write Primitive)
```bash
cd write_primitive
./run_exploit.sh
# Expected: Bus error: 10 (Crash)
```

### 2. Leak Demo (Read Primitive)
```bash
cd read_primitive
./run_exploit.sh
# Expected: LEAK: ... followed by crash
```

### 3. Flag/RCE Demo
```bash
cd flag
./run_exploit.sh
# Expected: [PWNED] CONTROL FLOW HIJACKED! ... CTF{...}
```

---

## 📜 Technical Analysis

### Vulnerability Overview
**CVE-2023-5841** is a heap-based buffer overflow in the `generic_unpack_deep` function of `libOpenEXRCore`. It specifically affects the processing of **Deep Scanline** images.

### Root Cause
The vulnerability stems from improper validation of the `sample_count` table in the EXR file headers.
1.  The library reads `sample_count` for each pixel from the file.
2.  It uses this value as a loop counter in the `UNPACK_SAMPLES` macro to copy data from the file (`src`) to the heap buffer (`decode_to_ptr`).
3.  **The Flaw**: The library does **not** verify if `sample_count * bytes_per_pixel` fits within the allocated destination buffer.
4.  **Exploit**: An attacker provides a massive value (e.g., `16,777,157`). The loops writes ~64MB of data into a small buffer, overwriting adjacent heap objects.

### exploitation Primitives developed

#### 1. Write Primitive (Overflow)
We confirmed the ability to write arbitrary or zeroed data past the buffer boundary.
*   **Result**: Immediate crash when the write hits non-mapped memory (Guard Page).
*   **Relevance**: Denial of Service (DoS).

#### 2. Read Primitive (Info Leak)
The `UNPACK_SAMPLES` macro also increments the source pointer (`src`) based on the massive sample count.
*   **Result**: The process reads massive amounts of heap memory to copy it to the destination.
*   **Relevance**: If the output buffer could be retrieved (e.g., via a side channel or saved file), it would leak sensitive process memory.

#### 3. Control Flow Hijack (Flag)
We demonstrated that with precise "Heap Grooming", this overflow leads to Arbitrary Code Execution.
*   **Method**: We allocated a `UnsuspectingVictim` struct (containing a function pointer) immediately after the vulnerable buffer.
*   **Result**: The overflow overwrote the victim's callback pointer. When the application later used this object, it jumped to our target function (`flag1`).

### Impact on iOS
This vulnerability affects **iOS versions prior to 18.0** (tested on iOS 17.3).
*   **Core Service**: The **Model I/O** framework and system-level image parsers use OpenEXR.
*   **Attack Vector**: Sending a malicious `.exr` file via iMessage, AirDrop, or embedding it in an app resource can trigger the crash.
*   **Status**: Fixed in iOS 18.0.

---

## Remediation
Upgrade to **OpenEXR v3.2.2** or later. Ensure that `totsamps` (total samples) is validated against the chunk size before unpacking deep scanline data.
