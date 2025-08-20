#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <string_view>
#include <algorithm>

namespace io {
    inline std::string trim(std::string s) {
        auto issp = [](unsigned char c){ return std::isspace(c); };
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), [&](char ch){ return !issp((unsigned char)ch); }));
        s.erase(std::find_if(s.rbegin(), s.rend(), [&](char ch){ return !issp((unsigned char)ch); }).base(), s.end());
        return s;
    }

    inline void strip_bom(std::string& s) {
        if (s.size() >= 3 && (unsigned char)s[0]==0xEF && (unsigned char)s[1]==0xBB && (unsigned char)s[2]==0xBF) s.erase(0, 3);
    }

    inline bool parse_token(std::string t, int& out) {
        while (!t.empty() && t.back()==',') t.pop_back();
        if (t.empty()) return false;
        std::transform(t.begin(), t.end(), t.begin(), [](unsigned char c){ return (char)std::toupper(c); });
        if (t=="?" || t=="??") { out = -1; return true; }
        if (t.size()==2 && (t[0]=='?' || t[1]=='?')) { out = -1; return true; }
        if (t.rfind("0X",0)==0) t = t.substr(2);
        if (t.size()!=2) return false;
        auto hv = [](char c)->int{ if (c>='0'&&c<='9') return c-'0'; if (c>='A'&&c<='F') return c-'A'+10; return -1; };
        int hi = hv(t[0]), lo = hv(t[1]);
        if (hi<0||lo<0) return false;
        out = (hi<<4)|lo;
        return true;
    }

    inline bool split_name_aob(std::string s, std::string& name, std::string& aob) {
        auto pos_comment = s.find_first_of(";#");
        if (pos_comment != std::string::npos) s = s.substr(0, pos_comment);
        s = trim(std::move(s));
        if (s.empty()) return false;
        size_t sep = s.find('=');
        if (sep == std::string::npos) sep = s.find(':');
        if (sep != std::string::npos) {
            name = trim(s.substr(0, sep));
            aob  = trim(s.substr(sep+1));
            if (!aob.empty() && aob.front()=='"' && aob.back()=='"' && aob.size()>=2) aob = aob.substr(1, aob.size()-2);
            return !name.empty() && !aob.empty();
        }
        auto sp = s.find_first_of(" \t");
        if (sp == std::string::npos) return false;
        name = trim(s.substr(0, sp));
        aob  = trim(s.substr(sp+1));
        if (!aob.empty() && aob.front()=='"' && aob.back()=='"' && aob.size()>=2) aob = aob.substr(1, aob.size()-2);
        return !name.empty() && !aob.empty();
    }

    inline std::vector<std::pair<std::string, std::vector<int>>> ReadPatterns(const std::string& filename, bool is64Bit) {
        std::ifstream f(filename, std::ios::binary);
        std::vector<std::pair<std::string, std::vector<int>>> out;
        if (!f) return out;
        std::string line;
        bool first = true;
        int section = 0;
        while (std::getline(f, line)) {
            if (first) { strip_bom(line); first = false; }
            line = trim(std::move(line));
            if (line.empty()) continue;
            if (line[0]=='#') {
                if (line.find("32BIT") != std::string::npos) section = 32;
                else if (line.find("64BIT") != std::string::npos) section = 64;
                else section = 0;
                continue;
            }
            if (section != 0) {
                if (is64Bit && section != 64) continue;
                if (!is64Bit && section != 32) continue;
            }
            std::string name, aob;
            if (!split_name_aob(line, name, aob)) continue;
            std::vector<int> bytes;
            size_t i = 0, n = aob.size();
            while (i < n) {
                while (i < n && std::isspace((unsigned char)aob[i])) ++i;
                size_t j = i;
                while (j < n && !std::isspace((unsigned char)aob[j])) ++j;
                if (i == j) break;
                int v = 0;
                if (parse_token(aob.substr(i, j - i), v)) bytes.push_back(v);
                i = j;
            }
            if (!bytes.empty()) out.emplace_back(std::move(name), std::move(bytes));
        }
        return out;
    }
}
