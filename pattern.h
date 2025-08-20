#pragma once
#include <string>
#include <vector>
#include <string_view>
#include <cstdint>
#include <cctype>

namespace scan {

    struct PatternData {
        std::string name;
        std::vector<uint8_t> bytes;
        std::vector<uint8_t> mask;
        size_t size;
    };

    inline std::vector<int> PatternToBytes(std::string_view pattern) {
        std::vector<int> bytes;
        size_t start = 0;
        while (start < pattern.size()) {
            while (start < pattern.size() && std::isspace(static_cast<unsigned char>(pattern[start])))
                ++start;
            if (start >= pattern.size()) break;

            size_t end = pattern.find(' ', start);
            if (end == std::string_view::npos) end = pattern.size();
            auto token = pattern.substr(start, end - start);
            if (token == "??" || token == "?")
                bytes.push_back(-1);
            else
                bytes.push_back(std::stoi(std::string(token), nullptr, 16));
            start = end;
        }
        return bytes;
    }

}
