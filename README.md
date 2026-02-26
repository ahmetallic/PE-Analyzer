# PE-Analyzer

PE-Detective is a command-line tool for inspecting the internal structure of Windows 32-bit and 64-bit binaries (.exe` and .dll files).

I built this to get a better understanding of the Portable Executable (PE) format and to practice manual binary parsing without relying on heavy external libraries like `DbgHelp`. It reads the bytes directly from disk using memory mapping, meaning it's fast and can handle large files efficiently.

## Features

- **Header Analysis**: Parses and displays the DOS Header and NT Headers (Signature, Machine Architecture, Timestamp).
- **Section Table Dump**: Lists all sections (e.g., `.text`, `.data`, `.rsrc`) along with their virtual addresses and raw sizes.
- **Memory Mapped**: Uses `CreateFileMapping` to handle file I/O, avoiding the overhead of loading the entire binary into a buffer.
- **Safety Checks**: Validates DOS and PE signatures to ensure the file is a valid Windows executable.

## Building

This project is self-contained and only requires the standard Windows SDK.

**Visual Studio:**
1. Create a new "Empty Project (C++)".
2. Add `main.cpp`, `PEAnalyzer.cpp`, and `PEAnalyzer.h`.
3. Build the solution.

**Command Line (MSVC):**
Run the following from your developer command prompt:
```cmd
cl /EHsc main.cpp PEAnalyzer.cpp /Fe:PEAnalyzer.exe
```

## Usage
```cmd
PEAnalyzer.exe "C:\Windows\System32\notepad.exe
```

**Output Example**
=== DOS HEADER ===
Magic Number: 5a4d (MZ)
Offset to NT Headers: 0xe0

=== NT HEADERS ===
Signature: 4550 (PE)
Machine Arch: 0x8664 (x64)
Number of Sections: 6
Time Stamp: 2026-02-25 09:14:32

=== SECTION HEADERS ===
Name      Virtual Size   Virtual Addr   Raw Size
.text     0x2e000        0x1000         0x2e000      
.rdata    0x15000        0x2f000        0x15000      
.data     0x800          0x44000        0x1000



