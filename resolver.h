#pragma once
#include <Windows.h>
#include <cstdint>
#include <cstddef>
#include "reader.h"

namespace scan {
    inline uintptr_t ExtractPointerFromData(const uint8_t* data, size_t dataSize, uintptr_t instrAddr) {
        if (!data || dataSize < 5) return 0;
        if (dataSize >= 5 && data[0] == 0xE8) {
            int32_t disp = *reinterpret_cast<const int32_t*>(data + 1);
            return instrAddr + 5 + disp;
        }
        if (dataSize >= 7 && data[0] == 0x48 && data[1] == 0x8B && (data[2] & 0xC7) == 0x05) {
            int32_t disp = *reinterpret_cast<const int32_t*>(data + 3);
            return instrAddr + 7 + disp;
        }
        if (dataSize >= 7 && data[0] == 0x48 && data[1] == 0x8D && (data[2] & 0xC7) == 0x05) {
            int32_t disp = *reinterpret_cast<const int32_t*>(data + 3);
            return instrAddr + 7 + disp;
        }
        if (dataSize >= 8 && (data[0] & 0xF8) == 0x40 && data[1] == 0x83 && data[2] == 0x3D) {
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