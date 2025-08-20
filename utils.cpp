#include "includes.h"
#include <TlHelp32.h>
#include <thread>
#include <regex>
#include <fstream>
#include <vector>
#include <string>
#include <iostream>
#include <immintrin.h>
typedef NTSTATUS(WINAPI* NtReadVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToRead,
    PULONG NumberOfBytesRead
    );
NtReadVirtualMemory_t NtReadVirtualMemoryFunc = nullptr;

bool LoadNtReadVirtualMemory() {
    HMODULE hNtdll = GetModuleHandleA(OXOR("ntdll.dll"));
    if (!hNtdll)
        return false;
    NtReadVirtualMemoryFunc = reinterpret_cast<NtReadVirtualMemory_t>(
        GetProcAddress(hNtdll, OXOR("NtReadVirtualMemory"))
        );
    return (NtReadVirtualMemoryFunc != nullptr);
}

bool ReadMemory(HANDLE hProc, LPCVOID base, BYTE* buffer, SIZE_T size, SIZE_T& bytesRead) {
    if (!NtReadVirtualMemoryFunc)
        return false;
    NTSTATUS status = NtReadVirtualMemoryFunc(hProc, const_cast<PVOID>(base), buffer,
        (ULONG)size, reinterpret_cast<PULONG>(&bytesRead));
    return (status >= 0);
}

Config ReadConfig(const std::string& configPath) {
    Config cfg{ true, false, false, false, false };
    std::ifstream f(configPath);
    if (!f) {
        std::cerr << OXOR("Warning: Could not open ") << configPath
            << OXOR(". Defaulting to 64-bit, CE_TABLE=false, Detailed_R=false, byName=false.\n");
        return cfg;
    }
    std::string line;
    while (std::getline(f, line)) {
        line = std::regex_replace(line, std::regex(OXOR("^\\s+|\\s+$")), OXOR(""));
        if (line.empty() || line[0] == ';')
            continue;
        if (line.find(OXOR("Arch:32")) != std::string::npos)
            cfg.is64Bit = false;
        else if (line.find(OXOR("Arch:64")) != std::string::npos)
            cfg.is64Bit = true;
        if (line.find(OXOR("CE_TABLE")) != std::string::npos) {
            cfg.ceTable = (line.find(OXOR("true")) != std::string::npos);
        }
        if (line.find(OXOR("Detailed_R")) != std::string::npos) {
            cfg.detailedR = (line.find(OXOR("true")) != std::string::npos);
        }
        if (line.find(OXOR("byName")) != std::string::npos) {
            cfg.byName = (line.find(OXOR("true")) != std::string::npos);
        }
        if (line.find(OXOR("offsets")) != std::string::npos) {
            cfg.generateOffsets = (line.find(OXOR("true")) != std::string::npos);
        }
    }
    return cfg;
}

std::string GetExeDirectory() {
    char path[MAX_PATH];
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    std::string exePath(path);
    size_t pos = exePath.find_last_of(OXOR("\\/"));
    return (pos != std::string::npos) ? exePath.substr(0, pos) : exePath;
}

DWORD GetProcessIDByClass(const std::string& className) {
    DWORD pid = 0;
    while (!pid) {
        HWND hWnd = FindWindowA(className.c_str(), nullptr);
        if (hWnd) {
            GetWindowThreadProcessId(hWnd, &pid);
        }
        if (!pid) {
            std::cout << "Waiting for Maplestory...\n";
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
    return pid;
}

DWORD GetProcessIDByName(const std::string& processName) {
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnap, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, processName.c_str()) == 0) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    while (!pid) {
        std::cout << "Waiting for " << processName << "...\n";
        std::this_thread::sleep_for(std::chrono::seconds(5));
        hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe; 
            pe.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnap, &pe)) {
                do {
                    if (_stricmp(pe.szExeFile, processName.c_str()) == 0) {
                        pid = pe.th32ProcessID;
                        break;
                    }
                } while (Process32Next(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
    }
    return pid;
}


HANDLE OpenTargetProcess(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc)
        std::cerr << OXOR("Error: Unable to open process.\n");
    return hProc;
}

std::vector<MEMORY_BASIC_INFORMATION> GetTargetRegions(HANDLE hProc, bool limitToModule, const std::string& moduleName) {
    std::vector<MEMORY_BASIC_INFORMATION> regions;
    if (limitToModule) {
        MODULEENTRY32 me = { 0 };
        me.dwSize = sizeof(MODULEENTRY32);
        DWORD pid = GetProcessId(hProc);
        HANDLE modSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (modSnap != INVALID_HANDLE_VALUE) {
            if (Module32First(modSnap, &me)) {
                do {
                    if (_stricmp(me.szModule, moduleName.c_str()) == 0) {
                        MEMORY_BASIC_INFORMATION mbi = { 0 };
                        mbi.BaseAddress = me.modBaseAddr;
                        mbi.RegionSize = me.modBaseSize;
                        mbi.AllocationBase = me.modBaseAddr;
                        mbi.State = MEM_COMMIT;
                        mbi.Protect = PAGE_EXECUTE_READ;
                        regions.push_back(mbi);
                        break;
                    }
                } while (Module32Next(modSnap, &me));
            }
            CloseHandle(modSnap);
        }
    }
    else {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        uintptr_t addr = reinterpret_cast<uintptr_t>(sysInfo.lpMinimumApplicationAddress);
        uintptr_t maxAddr = reinterpret_cast<uintptr_t>(sysInfo.lpMaximumApplicationAddress);
        while (addr < maxAddr) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(hProc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) != sizeof(mbi))
                break;
            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ |
                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY)))
            {
                regions.push_back(mbi);
            }
            addr += mbi.RegionSize;
        }
    }
    return regions;
}

std::vector<int> PatternToBytes(std::string_view pattern) {
    std::vector<int> bytes;
    size_t start = 0;
    while (start < pattern.size()) {
        while (start < pattern.size() && isspace(static_cast<unsigned char>(pattern[start])))
            start++;
        if (start >= pattern.size())
            break;
        size_t end = pattern.find(' ', start);
        if (end == std::string_view::npos)
            end = pattern.size();
        auto token = pattern.substr(start, end - start);
        if (token == OXOR("??") || token == OXOR("?"))
            bytes.push_back(-1);
        else
            bytes.push_back(std::stoi(std::string(token), nullptr, 16));
        start = end;
    }
    return bytes;
}

std::vector<size_t> FindAllMatches(const BYTE* buffer, size_t dataSize,
    const std::vector<uint8_t>& patBytes, const std::vector<uint8_t>& patMask, size_t patSize) {
    std::vector<size_t> matches;
    size_t i = 0;
    while (i + patSize <= dataSize) {
        bool found = true;
        size_t j = 0;
        for (; j + 32 <= patSize; j += 32) {
            __m256i memChunk = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(buffer + i + j));
            __m256i patternChunk = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&patBytes[j]));
            __m256i maskChunk = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&patMask[j]));
            __m256i diff = _mm256_xor_si256(memChunk, patternChunk);
            __m256i maskedDiff = _mm256_and_si256(diff, maskChunk);
            __m256i cmp = _mm256_cmpeq_epi8(maskedDiff, _mm256_setzero_si256());
            int cmpMask = _mm256_movemask_epi8(cmp);
            if (cmpMask != 0xFFFFFFFF) {
                found = false;
                break;
            }
        }
        if (found && j < patSize) {
            for (; j < patSize; j++) {
                if (patMask[j] != 0 && buffer[i + j] != patBytes[j]) {
                    found = false;
                    break;
                }
            }
        }
        if (found) {
            matches.push_back(i);
        }
        i++;
    }
    return matches;
}

uintptr_t TryExtractPointer(HANDLE hProc, uintptr_t base, int maxOffset) {
    BYTE instr[16] = { 0 };
    for (int offset = 0; offset <= maxOffset; offset++) {
        SIZE_T bytesRead = 0;
        if (!ReadMemory(hProc, reinterpret_cast<LPCVOID>(base + offset), instr, sizeof(instr), bytesRead))
            continue;
        if (bytesRead < 7)
            continue;

        // CALL rel32 -> E8 xx xx xx xx (relative call)
        if (instr[0] == 0xE8 && bytesRead >= 5) {
            int32_t disp = *reinterpret_cast<int32_t*>(&instr[1]);
            return (base + offset) + 5 + disp;
        }

        // JMP rel32 -> E9 xx xx xx xx (relative jump)
        if (instr[0] == 0xE9 && bytesRead >= 5) {
            int32_t disp = *reinterpret_cast<int32_t*>(&instr[1]);
            return (base + offset) + 5 + disp;
        }

        // JZ rel32 -> 0F 84 xx xx xx xx (conditional jump if zero)
        if (instr[0] == 0x0F && instr[1] == 0x84 && bytesRead >= 6) {
            int32_t disp = *reinterpret_cast<int32_t*>(&instr[2]);
            return (base + offset) + 6 + disp;
        }

        // JNZ rel32 -> 0F 85 xx xx xx xx (conditional jump if not zero)
        if (instr[0] == 0x0F && instr[1] == 0x85 && bytesRead >= 6) {
            int32_t disp = *reinterpret_cast<int32_t*>(&instr[2]);
            return (base + offset) + 6 + disp;
        }

        // MOV rax, [rip+disp32] -> 48 8B 05 xx xx xx xx
        if (instr[0] == 0x48 && instr[1] == 0x8B && ((instr[2] & 0xC7) == 0x05) && bytesRead >= 7) {
            int32_t disp = *reinterpret_cast<int32_t*>(&instr[3]);
            return (base + offset) + 7 + disp;
        }

        // CMP [rip+disp32], imm8 -> 48 83 3D xx xx xx xx xx
        if (instr[0] == 0x48 && instr[1] == 0x83 && instr[2] == 0x3D && bytesRead >= 8) {
            int32_t disp = *reinterpret_cast<int32_t*>(&instr[3]);
            return (base + offset) + 8 + disp;
        }

        // F2 0F 5E/59/58/10 05 xx xx xx xx (SSE ops with RIP-relative address)
        if (bytesRead >= 8 && instr[0] == 0xF2 && instr[1] == 0x0F &&
            (instr[2] == 0x5E || instr[2] == 0x59 || instr[2] == 0x58 || instr[2] == 0x10) && instr[3] == 0x05)
        {
            int32_t disp = *reinterpret_cast<int32_t*>(&instr[4]);
            return (base + offset) + 8 + disp;
        }
    }
    return 0;
}


std::vector<std::pair<std::string, std::vector<int>>> ReadPatterns(const std::string& filename, bool is64Bit) {
    std::ifstream file(filename);
    std::vector<std::pair<std::string, std::vector<int>>> patterns;
    if (!file) {
        std::cerr << OXOR("Error: Unable to open pattern file: ") << filename << OXOR("\n");
        return patterns;
    }
    std::string line;
    std::regex patternRegex(OXOR(R"((\w+)\s*=\s*\"([0-9A-Fa-f?\s]+)\")"));
    int currentSection = 0;
    while (std::getline(file, line)) {
        line = std::regex_replace(line, std::regex(OXOR("^\\s+|\\s+$")), OXOR(""));
        if (line.empty())
            continue;
        if (line[0] == '#') {
            if (line.find(OXOR("32BIT")) != std::string::npos)
                currentSection = 32;
            else if (line.find(OXOR("64BIT")) != std::string::npos)
                currentSection = 64;
            else
                currentSection = 0;
            continue;
        }
        if (currentSection != 0 &&
            ((is64Bit && currentSection != 64) ||
                (!is64Bit && currentSection != 32)))
        {
            continue;
        }
        std::smatch matches;
        if (std::regex_search(line, matches, patternRegex)) {
            patterns.emplace_back(matches[1].str(), std::vector<int>());
            std::string patStr = matches[2].str();
            std::vector<int> bytes;
            size_t start = 0;
            while (start < patStr.size()) {
                while (start < patStr.size() && isspace(static_cast<unsigned char>(patStr[start])))
                    start++;
                if (start >= patStr.size())
                    break;
                size_t end = patStr.find(' ', start);
                if (end == std::string::npos)
                    end = patStr.size();
                auto token = patStr.substr(start, end - start);
                if (token == OXOR("??") || token == OXOR("?"))
                    bytes.push_back(-1);
                else
                    bytes.push_back(std::stoi(token, nullptr, 16));
                start = end;
            }
            patterns.back().second = std::move(bytes);
        }
    }
    return patterns;
}

void SaveResultsCEStyle(const std::vector<std::pair<std::string, uintptr_t>>& results, const std::string& filePath) {
    std::unordered_map<std::string, std::vector<uintptr_t>> patternMap;
    patternMap.reserve(results.size());
    for (auto& r : results) {
        patternMap[r.first].push_back(r.second);
    }
    std::ofstream out(filePath, std::ios::trunc);
    if (!out) {
        std::cerr << OXOR("Error: Unable to open ") << filePath << OXOR("\n");
        return;
    }
    for (auto& kv : patternMap) {
        const std::string& patternName = kv.first;
        const auto& addrs = kv.second;
        if (addrs.empty())
            continue;
        if (addrs.size() == 1) {
            out << OXOR("define(") << patternName << OXOR(", 0x")
                << std::hex << std::uppercase << addrs[0] << OXOR(")\n");
            out << OXOR("registersymbol(") << patternName << OXOR(")\n");
        }
        else {
            for (size_t i = 0; i < addrs.size(); i++) {
                out << OXOR("define(") << patternName << OXOR("_") << (i + 1)
                    << OXOR(", 0x") << std::hex << std::uppercase << addrs[i] << OXOR(")\n");
                out << OXOR("registersymbol(") << patternName << OXOR("_") << (i + 1) << OXOR(")");
            }
            out << OXOR("\n");
        }
    }
    out.close();
    std::cout << OXOR("Results saved (CE-style) to ") << filePath << OXOR("\n");
}


void SaveResultsOffsets(const std::vector<std::pair<std::string, uintptr_t>>& results, const std::string& filePath) {
    std::unordered_map<std::string, std::vector<std::pair<std::string, uintptr_t>>> patternMap;
    patternMap.reserve(results.size());

    for (const auto& r : results) {
        const auto& name = r.first;
        uintptr_t addr = r.second;
        if (name.size() > 4 && name.compare(name.size() - 4, 4, OXOR("_PTR")) == 0)
            continue;

        std::string cleanName = name;

        if (cleanName.size() > 5 && cleanName.compare(cleanName.size() - 5, 5, OXOR("_Base")) == 0)
            cleanName = cleanName.substr(0, cleanName.size() - 5);
        if (cleanName.find(OXOR("Packet")) != std::string::npos ||
            cleanName.find(OXOR("Decode")) != std::string::npos ||
            cleanName.find(OXOR("Encode")) != std::string::npos)
        {
            patternMap[OXOR("packets")].emplace_back(cleanName, addr);
        }
        else if (cleanName.size() > 5 && (cleanName.substr(cleanName.size() - 5) == OXOR("_CALL") || cleanName.substr(cleanName.size() - 5) == OXOR("_FUNC")))
        {
            patternMap[OXOR("functions")].emplace_back(cleanName, addr);
        }
        else
        {
            patternMap[OXOR("globals")].emplace_back(cleanName, addr);
        }
    }

    std::ofstream out(filePath, std::ios::trunc);
    if (!out) {
        std::cerr << OXOR("Error: Unable to open ") << filePath << OXOR("\n");
        return;
    }

    out << OXOR("#pragma once\n");
    out << OXOR("#include <cstdint>\n\n");
    out << OXOR("namespace maple {\n\n");

    for (auto& kv : patternMap) {
        const std::string& namespaceName = kv.first;
        const auto& entries = kv.second;
        if (entries.empty())
            continue;

        out << OXOR("    namespace ") << namespaceName << OXOR(" {\n");
        out << OXOR("        inline constexpr uintptr_t\n");

        for (size_t i = 0; i < entries.size(); ++i) {
            const auto& [name, addr] = entries[i];
            out << OXOR("            ") << name << OXOR(" = 0x") << std::hex << std::uppercase << addr;
            if (i != entries.size() - 1)
                out << OXOR(",\n");
            else
                out << OXOR(";\n");
        }

        out << OXOR("    }\n\n");
    }

    out << OXOR("}\n");
    out.close();

    std::cout << OXOR("Results saved to ") << filePath << OXOR("\n");
}



void SaveResultsNormal(const std::vector<std::pair<std::string, uintptr_t>>& results, const std::string& filePath, bool is64Bit) {
    std::ofstream outFile(filePath, std::ios::trunc);
    if (!outFile) {
        std::cerr << OXOR("Error: Unable to open ") << filePath << OXOR("\n");
        return;
    }
    if (is64Bit)
        outFile << OXOR("64BIT Addresses:\n###################\n");
    else
        outFile << OXOR("32BIT Addresses:\n###################\n");
    for (const auto& r : results) {
        outFile << r.first << OXOR(" : 0x") << std::hex << std::uppercase << r.second << "\n";
    }
    outFile << OXOR("#######################\n");
    std::cout << OXOR("Results saved to ") << filePath << OXOR("\n");
}
