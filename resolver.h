#pragma once
#include <Windows.h>
#include <cstdint>
#include <cstddef>
#include "reader.h"

namespace scan {
    inline uintptr_t ExtractPointerFromData(const uint8_t* data, size_t dataSize, uintptr_t instrAddr) {
        if (!data || dataSize < 5) return 0;
        const size_t limit = dataSize > 32 ? 32 : dataSize;
        for (size_t off = 0; off + 5 <= limit; ++off) {
            const uint8_t* p = data + off;
            if (p[0] == 0xE9 && off + 5 <= dataSize) {
                int32_t rel = *reinterpret_cast<const int32_t*>(p + 1);
                return instrAddr + off + 5 + rel;
            }
            if (p[0] == 0xE8 && off + 5 <= dataSize) {
                int32_t rel = *reinterpret_cast<const int32_t*>(p + 1);
                return instrAddr + off + 5 + rel;
            }
            if (off + 7 <= dataSize && p[0] == 0x48 && p[1] == 0x8B && (p[2] & 0xC7) == 0x05) {
                int32_t disp = *reinterpret_cast<const int32_t*>(p + 3);
                return instrAddr + off + 7 + disp;
            }
            if (off + 7 <= dataSize && p[0] == 0x48 && p[1] == 0x8D && (p[2] & 0xC7) == 0x05) {
                int32_t disp = *reinterpret_cast<const int32_t*>(p + 3);
                return instrAddr + off + 7 + disp;
            }
            if (off + 8 <= dataSize && (p[0] & 0xF8) == 0x40 && p[1] == 0x83 && p[2] == 0x3D) {
                int32_t disp = *reinterpret_cast<const int32_t*>(p + 3);
                return instrAddr + off + 8 + disp;
            }
            if (off + 8 <= dataSize && p[0] == 0xF2 && p[1] == 0x0F &&
                (p[2] == 0x10 || p[2] == 0x5E || p[2] == 0x59 || p[2] == 0x58) &&
                p[3] == 0x05) {
                int32_t disp = *reinterpret_cast<const int32_t*>(p + 4);
                return instrAddr + off + 8 + disp;
            }
        }
        return 0;
    }

    inline uint32_t TryExtractOffset(const Reader& reader, HANDLE hProc, uintptr_t base, int maxOffset = 4) {
        uint8_t instr[8] = {};
        for (int off = 0; off <= maxOffset; ++off) {
            size_t got = 0;
            if (!reader.Read(hProc, reinterpret_cast<LPCVOID>(base + off), instr, sizeof(instr), got)) continue;
            if (got < 4) continue;
            uint8_t rex = instr[0];
            if ((rex & 0xF0) == 0x40 && (rex & 0x08) && instr[1] == 0x8B) {
                uint8_t mod = instr[2] >> 6;
                if (mod == 1) return static_cast<uint32_t>(uint8_t(*reinterpret_cast<int8_t*>(instr + 3)));
                if (mod == 2 && got >= 7) return static_cast<uint32_t>(*reinterpret_cast<int32_t*>(instr + 3));
            }
        }
        return 0;
    }
}