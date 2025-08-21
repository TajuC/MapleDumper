#pragma once
#include <Windows.h>
#include <cstdint>
#include <cstddef>
#include "reader.h"

namespace scan {
    inline bool DecodeRelTarget(const uint8_t* p, size_t n, uintptr_t ip, uintptr_t& out) {
        if (n >= 5 && (p[0] == 0xE8 || p[0] == 0xE9)) {
            int32_t d = *reinterpret_cast<const int32_t*>(p + 1);
            out = ip + 5 + d;
            return true;
        }
        if (n >= 2 && p[0] == 0xEB) {
            int8_t d = *reinterpret_cast<const int8_t*>(p + 1);
            out = ip + 2 + d;
            return true;
        }
        if (n >= 6 && p[0] == 0x0F && (p[1] >= 0x80 && p[1] <= 0x8F)) {
            int32_t d = *reinterpret_cast<const int32_t*>(p + 2);
            out = ip + 6 + d;
            return true;
        }
        if (n >= 2 && (p[0] >= 0x70 && p[0] <= 0x7F)) {
            int8_t d = *reinterpret_cast<const int8_t*>(p + 1);
            out = ip + 2 + d;
            return true;
        }
        return false;
    }

    inline uintptr_t ExtractPointerFromData(const uint8_t* data, size_t dataSize, uintptr_t instrAddr) {
        if (!data || dataSize < 2) return 0;
        for (size_t i = 0; i < dataSize; ++i) {
            const uint8_t* p = data + i;
            size_t n = dataSize - i;
            uintptr_t ip = instrAddr + i;
            uintptr_t tgt = 0;
            if (DecodeRelTarget(p, n, ip, tgt)) return tgt;
            if (n >= 7 && p[0] == 0x48 && p[1] == 0x8B && (p[2] & 0xC7) == 0x05) {
                int32_t d = *reinterpret_cast<const int32_t*>(p + 3);
                return ip + 7 + d;
            }
            if (n >= 7 && p[0] == 0x48 && p[1] == 0x8D && (p[2] & 0xC7) == 0x05) {
                int32_t d = *reinterpret_cast<const int32_t*>(p + 3);
                return ip + 7 + d;
            }
            if (n >= 8 && (p[0] & 0xF8) == 0x40 && p[1] == 0x83 && p[2] == 0x3D) {
                int32_t d = *reinterpret_cast<const int32_t*>(p + 3);
                return ip + 8 + d;
            }
            if (n >= 8 && p[0] == 0xF2 && p[1] == 0x0F &&
                (p[2] == 0x10 || p[2] == 0x58 || p[2] == 0x59 || p[2] == 0x5E) &&
                p[3] == 0x05) {
                int32_t d = *reinterpret_cast<const int32_t*>(p + 4);
                return ip + 8 + d;
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