// resolver.h
#pragma once
#include <Windows.h>
#include <cstdint>
#include "reader.h"

namespace scan {
    inline uintptr_t ExtractPointerFromData(const uint8_t* data, size_t dataSize, uintptr_t instrAddr) {
        if (dataSize < 5) return 0;
        uintptr_t firstTarget = 0;
        int callCount = 0;
        for (size_t i = 0; i + 5 <= dataSize; ++i) {
            if (data[i] == 0xE8) {
                int32_t rel = *reinterpret_cast<const int32_t*>(data + i + 1);
                uintptr_t targ = instrAddr + i + 5 + rel;
                ++callCount;
                if (callCount == 1) firstTarget = targ;
                else if (callCount == 2) return targ;
            }
        }
        if (callCount == 1) return firstTarget;
        if (data[0] == 0xE9 && dataSize >= 5) {
            int32_t rel = *reinterpret_cast<const int32_t*>(data + 1);
            return instrAddr + 5 + rel;
        }
        if (dataSize >= 6 && data[0] == 0x0F && (data[1] == 0x84 || data[1] == 0x85)) {
            int32_t rel = *reinterpret_cast<const int32_t*>(data + 2);
            return instrAddr + 6 + rel;
        }
        if ((data[0] & 0xF8) == 0x40 && data[1] == 0x8B && (data[2] & 0xC7) == 0x05 && dataSize >= 7) {
            int32_t disp = *reinterpret_cast<const int32_t*>(data + 3);
            return instrAddr + 7 + disp;
        }
        if ((data[0] & 0xF8) == 0x40 && data[1] == 0x83 && data[2] == 0x3D && dataSize >= 8) {
            int32_t disp = *reinterpret_cast<const int32_t*>(data + 3);
            return instrAddr + 8 + disp;
        }
        if (dataSize >= 8 && data[0] == 0xF2 && data[1] == 0x0F &&
            (data[2] == 0x10 || data[2] == 0x5E || data[2] == 0x59 || data[2] == 0x58) &&
            data[3] == 0x05) {
            int32_t disp = *reinterpret_cast<const int32_t*>(data + 4);
            return instrAddr + 8 + disp;
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
