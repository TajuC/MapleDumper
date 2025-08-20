# MapleDumper

High‑performance AOB/pattern scanner and offset categorizer for Windows x64 processes. 
MapleDumper uses an AVX2‑accelerated masked matcher, tolerant pattern loader, and robust RIP‑relative/jump resolvers to locate pointers and function targets reliably. 
Results are exported to a human‑readable report and a C/C++ header for direct use in projects.

---

## Overview
- Scans a live process (e.g., MapleStory) using `NtReadVirtualMemory`.
- Enumerates and coalesces committed memory regions to avoid page‑boundary misses.
- AVX2 SIMD matcher with wildcard support and strict tail handling.
- Pattern loader accepts flexible syntax and 32/64‑bit sections.
- Resolver extracts targets for `jmp/call rel32`, RIP‑relative loads (`mov/lea [rip+disp32]`), selected `cmp` and SSE load forms.
- Categorizer writes `update.txt` and `offsets.h` with stable symbol names.
- Configurable attach mode (process name or window class) via `config.ini`.

---

## Features
- **Masked AVX2 matcher**: fast anchor prefilter + exact masked compare, supports `?` and `??` wildcards.
- **Region coalescing**: merges adjacent readable/exec regions so patterns spanning boundaries are not missed.
- **Robust resolver**: correct address computation for:
  - `E8 rel32` (call), `E9 rel32` (jmp)
  - `48 8B 0D disp32`, `48 8D 0D disp32` (RIP‑relative)
  - `REX 83 3D disp32 imm8/imm32` guards
  - Selected `F2 0F 10/58/59/5E 05 disp32` vector loads
- **Tolerant patterns**: parser accepts `AA`, `0xAA`, commas, mixed whitespace, `?` or `??` wildcards, and optional `#32BIT` / `#64BIT` sections.
- **Deterministic output**: duplicate suppression, sorted categories, single match per signature by default.

---

## Build
- Visual Studio 2019/2022, x64 Release.
- Language standard: C++17 or newer.
- Enable AVX2 (`/arch:AVX2`) for best performance.
- Windows SDK 10+.
- Project structure (key files):
  - `main.cpp`, `utils.cpp`
  - `includes.h`, `libs.h`, `config.h`
  - `process.h`, `reader.h`, `ntapi.h`
  - `regions.h`, `scanner.h`, `pattern_loader.h`, `resolver.h`
  - `categorizer.h`, `save_offsets.h`, `save_plain.h`

---

## Run
1. Start the target process.
2. Place `MapleDumper.exe`, `patterns.txt`, and `config.ini` in the same directory.
3. Run MapleDumper **as Administrator**.
4. Results are written next to the executable:
   - `update.txt` – summary of found and not found patterns.
   - `offsets.h` – C/C++ header with resolved addresses.

> The tool does not take command‑line arguments; behavior is controlled by `config.ini` and `patterns.txt`.

---

## Configuration (`config.ini`)
```
Arch:64
CE_TABLE=true
Detailed_R=false
byName=false
offsets=true
```
- `Arch:64` or `Arch:32`. Determines which sections of `patterns.txt` to load.
- `CE_TABLE` toggles Cheat‑Engine‑style formatting in `update.txt`.
- `byName=true` to attach by process name (`MapleStory.exe`), `false` to attach by window class.
- `offsets` controls whether `offsets.h` is generated.

---

## Patterns (`patterns.txt`)
- Supported line forms:
  - `Name = AA BB CC ?? DD`
  - `Name: 0xAA 0xBB ?? DD`
  - `Name AA BB ?? DD`  
- Wildcards: `?` or `??`. Commas are allowed. Inline comments after `;` or `#` are ignored.
- Optional sections:
  - `#32BIT` … patterns for 32‑bit
  - `#64BIT` … patterns for 64‑bit
- Suffix conventions:
  - `*_PTR` – resolver returns the **address** referenced by RIP‑relative load or the **target** of `jmp/call rel32` (no dereference).
  - `*_EH_PTR` – resolver returns the resolved call target near a handler table. A `_Base` alias is emitted where appropriate.

**Examples**
```
CUserLocal_PTR = 48 8B 0D ? ? ? ? 48 85 C9 74 16 E8 ? ? ? ? 85 C0
EncodeStr_PTR  = E9 ? ? ? ? 8B 56 0C
CClickBase_PTR = 45 33 C0 48 8B 0D ? ? ? ? E8 ? ? ? ? EB 71
```

---

## How it works (high‑level)
1. Enable `SeDebugPrivilege`, locate the PID by name or class.
2. Enumerate memory with `VirtualQueryEx`, select committed readable/exec pages, and merge adjacent regions.
3. Read each region into a local buffer, scan with an AVX2 masked matcher, and compute absolute match addresses.
4. For `*_PTR` or `*_EH_PTR`, extract the correct **address** (RIP‑relative or rel32 target). No dereference is performed for offsets.
5. Categorize and write results to `update.txt` and `offsets.h`.

---

## Output
- `update.txt`  
  - Per‑pattern match count and a summary of FOUND/NOTFOUND.
- `offsets.h`  
  - One line per resolved symbol, e.g.:
    ```c
    CUserLocal = 0x00000001479E9298,
    EncodeStr  = 0x0000000140CFE6A0,
    CClickBase = 0x00000001479E9568,
    ```

---

## Troubleshooting
- **Immediate exit (code 1)**: run elevated; ensure `OpenProcess` rights are granted; confirm `byName` vs `byClass` in `config.ini`.
- **Miss at region boundary**: ensure you are on the build with region coalescing; keep patterns anchored to at least one fixed byte.
- **Duplicate entries**: the strict matcher prevents flood matches. If you still see duplicates from multiple patterns mapping to the same address, enable deduplication at emit time.

---

## License
MIT. See `LICENSE`.
