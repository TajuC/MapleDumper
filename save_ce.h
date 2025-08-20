#pragma once
#include <fstream>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <string>
#include <iomanip>

namespace io {

    inline void SaveResultsCEStyle(const std::vector<std::pair<std::string, uintptr_t>>& results,
        const std::string& path) {
        std::unordered_map<std::string, std::vector<uintptr_t>> grouped;
        for (const auto& [name, addr] : results)
            grouped[name].push_back(addr);

        std::ofstream out(path, std::ios::trunc);
        if (!out) {
            std::cerr << "[!] Failed to open output file: " << path << '\n';
            return;
        }

        for (const auto& [name, addrs] : grouped) {
            if (addrs.empty()) continue;
            if (addrs.size() == 1) {
                out << "define(" << name << ", 0x" << std::hex << std::uppercase << addrs[0] << ")\n";
                out << "registersymbol(" << name << ")\n";
            }
            else {
                for (size_t i = 0; i < addrs.size(); ++i) {
                    out << "define(" << name << '_' << (i + 1) << ", 0x"
                        << std::hex << std::uppercase << addrs[i] << ")\n";
                    out << "registersymbol(" << name << '_' << (i + 1) << ")\n";
                }
            }
        }

        std::cout << "[+] Results saved (CE-style) to " << path << '\n';
    }

}
