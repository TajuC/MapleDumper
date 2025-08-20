#pragma once
#include <string>
#include <fstream>
#include <regex>

namespace core {

    struct Config {
        bool is64Bit{ true };
        bool ceTable{ false };
        bool detailedR{ false };
        bool byName{ false };
        bool generateOffsets{ false };
    };

    inline Config ReadConfig(const std::string& path) {
        Config cfg;
        std::ifstream file(path);
        if (!file) return cfg;

        std::string line;
        std::regex trim(R"(^\s+|\s+$)");
        while (std::getline(file, line)) {
            line = std::regex_replace(line, trim, "");
            if (line.empty() || line[0] == ';') continue;

            if (line.contains("Arch:32")) cfg.is64Bit = false;
            else if (line.contains("Arch:64")) cfg.is64Bit = true;
            else if (line.contains("CE_TABLE")) cfg.ceTable = line.contains("true");
            else if (line.contains("Detailed_R")) cfg.detailedR = line.contains("true");
            else if (line.contains("byName")) cfg.byName = line.contains("true");
            else if (line.contains("offsets")) cfg.generateOffsets = line.contains("true");
        }

        return cfg;
    }

}
