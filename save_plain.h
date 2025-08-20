#pragma once
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>

namespace io {

    inline void SaveResultsText(const std::vector<std::pair<std::string, uintptr_t>>& results,
        const std::string& outPath,
        bool is64Bit) {
        std::ofstream out(outPath, std::ios::trunc);
        if (!out) {
            std::cerr << "[!] Failed to open output: " << outPath << "\n";
            return;
        }

        out << (is64Bit ? "64BIT Addresses:\n" : "32BIT Addresses:\n");
        out << "###################\n";
        for (const auto& [name, addr] : results) {
            out << name << " : 0x" << std::hex << std::uppercase << addr << "\n";
        }
        out << "###################\n";
        std::cout << "[+] Text results saved to " << outPath << "\n";
    }

}
