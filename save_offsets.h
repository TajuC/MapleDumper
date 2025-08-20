#pragma once
#include <fstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <iostream>
#include <iomanip>
#include "categorizer.h"

namespace io {

    inline void SaveResultsOffsets(
        const std::vector<std::pair<std::string, uintptr_t>>& results,
        const std::string& outPath)
    {
        std::unordered_map<std::string, std::vector<std::pair<std::string, uintptr_t>>> grouped;

        for (auto& [name, addr] : results) {
            if (name.size() > 4 && name.ends_with("_PTR"))
                continue;
            std::string clean = name;
            if (clean.ends_with("_Base"))
                clean.resize(clean.size() - 5);
            if (clean.ends_with("_OFF"))
                clean.resize(clean.size() - 4);
            std::string cat = io::CategorizeOffset(clean);
            grouped[cat].emplace_back(std::move(clean), addr);
        }

        std::ofstream out(outPath, std::ios::trunc);
        if (!out) {
            std::cerr << "[!] Failed to open output: " << outPath << "\n";
            return;
        }

        out << "#pragma once\n#include <cstdint>\n\nnamespace maple {\n\n";

        for (auto const& ns : { "globals", "offsets", "functions", "packets", "items" }) {
            auto it = grouped.find(ns);
            if (it == grouped.end() || it->second.empty())
                continue;

            auto& entries = it->second;
            out << "    namespace " << ns << " {\n"
                "        inline constexpr uintptr_t\n";

            for (size_t i = 0; i < entries.size(); ++i) {
                auto const& [entryName, addr] = entries[i];
                out << "            " << entryName
                    << " = 0x" << std::hex << std::uppercase << addr;
                if (i + 1 < entries.size()) out << ",\n";
                else                      out << ";\n";
            }

            out << std::dec
                << "    }\n\n";
        }

        out << "}\n";
        std::cout << "[+] Offsets saved to " << outPath << "\n";
    }

}
