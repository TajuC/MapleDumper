#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <immintrin.h>
#include <cstring>

namespace scan {
    inline bool MatchAt(const uint8_t* buf, size_t bufSize, const std::vector<uint8_t>& pat, const std::vector<uint8_t>& msk, size_t patSize, size_t pos) {
        if (pos + patSize > bufSize) return false;
        const uint8_t* b = buf + pos;
        for (size_t i = 0; i < patSize; ++i) {
            uint8_t mm = msk[i];
            if (mm && (((b[i] ^ pat[i]) & mm) != 0)) return false;
        }
        return true;
    }

    inline size_t ChooseAnchor(const std::vector<uint8_t>& mask) {
        for (size_t i = 0; i < mask.size(); ++i) if (mask[i] == 0xFF) return i;
        return static_cast<size_t>(-1);
    }

    inline bool IsJmpFollowPattern(const std::vector<uint8_t>& pattern, const std::vector<uint8_t>& mask) {
        if (pattern.size() < 6) return false;
        if (pattern[0] != 0xE9) return false;
        if (mask[0] != 0xFF) return false;
        if (mask.size() < 5) return false;
        return mask[1] == 0x00 && mask[2] == 0x00 && mask[3] == 0x00 && mask[4] == 0x00;
    }

    inline std::vector<size_t> FindAllMatches(const uint8_t* buffer, size_t dataSize, const std::vector<uint8_t>& pattern, const std::vector<uint8_t>& mask, size_t patternSize) {
        const uint8_t* hay = buffer;
        std::vector<size_t> out;
        if (patternSize == 0 || dataSize < patternSize) {
            if (IsJmpFollowPattern(pattern, mask) && dataSize >= 5) { 
                std::vector<uint8_t> pat5(pattern.begin(), pattern.begin() + 5);
                std::vector<uint8_t> msk5(mask.begin(), mask.begin() + 5);
                size_t anchor = 0;
                uint8_t a = pat5[anchor];
                __m256i va = _mm256_set1_epi8((char)a);
                size_t end = dataSize - 5;
                size_t i = 0;
                while (i <= end) {
                    size_t remain = dataSize - (i + anchor);
                    if (remain >= 32) {
                        __m256i v = _mm256_loadu_si256((const __m256i*)(hay + i + anchor));
                        __m256i eq = _mm256_cmpeq_epi8(v, va);
                        uint32_t bits = (uint32_t)_mm256_movemask_epi8(eq);
                        while (bits) {
    #if defined(_MSC_VER)
                            unsigned bit = _tzcnt_u32(bits);
    #else
                            unsigned bit = __builtin_ctz(bits);
    #endif
                            size_t pos = i + bit - anchor;
                            if (pos <= end && MatchAt(hay, dataSize, pat5, msk5, 5, pos)) out.push_back(pos);
                            bits &= bits - 1;
                        }
                        i += 32;
                    } else {
                        const void* p = std::memchr(hay + i + anchor, a, remain);
                        if (!p) break;
                        size_t hit = ((const uint8_t*)p - hay) - anchor;
                        if (hit <= end && MatchAt(hay, dataSize, pat5, msk5, 5, hit)) out.push_back(hit);
                        i = hit + 1;
                    }
                }
            }
            return out;
        }

        if (IsJmpFollowPattern(pattern, mask)) {
            std::vector<uint8_t> pat5(pattern.begin(), pattern.begin() + 5);
            std::vector<uint8_t> msk5(mask.begin(), mask.begin() + 5);
            return FindAllMatches(buffer, dataSize, pat5, msk5, 5);
        }

        size_t anchor = ChooseAnchor(mask);
        if (anchor == static_cast<size_t>(-1)) {
            out.reserve(dataSize - patternSize + 1);
            for (size_t i = 0; i + patternSize <= dataSize; ++i) out.push_back(i);
            return out;
        }
        uint8_t a = pattern[anchor];
        size_t end = dataSize - patternSize;
        __m256i va = _mm256_set1_epi8((char)a);
        size_t i = 0;
        while (i <= end) {
            size_t remain = dataSize - (i + anchor);
            if (remain >= 32) {
                __m256i v = _mm256_loadu_si256((const __m256i*)(hay + i + anchor));
                __m256i eq = _mm256_cmpeq_epi8(v, va);
                uint32_t bits = (uint32_t)_mm256_movemask_epi8(eq);
                while (bits) {
#if defined(_MSC_VER)
                    unsigned bit = _tzcnt_u32(bits);
#else
                    unsigned bit = __builtin_ctz(bits);
#endif
                    size_t pos = i + bit - anchor;
                    if (pos <= end && MatchAt(hay, dataSize, pattern, mask, patternSize, pos)) out.push_back(pos);
                    bits &= bits - 1;
                }
                i += 32;
            } else {
                const void* p = std::memchr(hay + i + anchor, a, remain);
                if (!p) break;
                size_t hit = ((const uint8_t*)p - hay) - anchor;
                if (hit <= end && MatchAt(hay, dataSize, pattern, mask, patternSize, hit)) out.push_back(hit);
                i = hit + 1;
            }
        }
        return out;
    }

    inline void FindAllMatchesWithBase(const uint8_t* buffer, size_t dataSize, const std::vector<uint8_t>& pattern, const std::vector<uint8_t>& mask, size_t patternSize, uintptr_t regionBase, std::vector<uintptr_t>& absoluteMatches) {
        absoluteMatches.clear();
        auto rel = FindAllMatches(buffer, dataSize, pattern, mask, patternSize);
        absoluteMatches.reserve(rel.size());
        for (auto off : rel) absoluteMatches.push_back(regionBase + off);
    }
}
