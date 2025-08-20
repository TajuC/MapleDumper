#ifndef UTILS_H
#define UTILS_H
#include "includes.h"
// Include your compile–time obfuscation header.
#define OXOR(x) WRAPPER_MARCO(x)

// Configuration structure.
struct Config {
    bool is64Bit;
    bool ceTable;
    bool detailedR;
    bool byName; 
    bool generateOffsets;
};

// Memory reading functions.
bool LoadNtReadVirtualMemory();
bool ReadMemory(HANDLE hProc, LPCVOID base, BYTE* buffer, SIZE_T size, SIZE_T& bytesRead);

// Configuration file reading.
Config ReadConfig(const std::string& configPath);

// Miscellaneous utility functions.
std::string GetExeDirectory();
DWORD GetProcessIDByClass(const std::string& className);
DWORD GetProcessIDByName(const std::string& processName); // New function.
HANDLE OpenTargetProcess(DWORD pid);

// Memory region gathering.
std::vector<MEMORY_BASIC_INFORMATION> GetTargetRegions(HANDLE hProc, bool limitToModule, const std::string& moduleName);

// Pattern conversion and scanning.
std::vector<int> PatternToBytes(std::string_view pattern);
std::vector<size_t> FindAllMatches(const BYTE* buffer, size_t dataSize,
    const std::vector<uint8_t>& patBytes, const std::vector<uint8_t>& patMask, size_t patSize);
uintptr_t TryExtractPointer(HANDLE hProc, uintptr_t base, int maxOffset = 4);

// Structure for pattern data.
struct PatternData {
    std::string name;
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask;
    size_t size;
};

// Pattern file reading and result saving.
std::vector<std::pair<std::string, std::vector<int>>> ReadPatterns(const std::string& filename, bool is64Bit);
void SaveResultsCEStyle(const std::vector<std::pair<std::string, uintptr_t>>& results, const std::string& filePath);
void SaveResultsNormal(const std::vector<std::pair<std::string, uintptr_t>>& results, const std::string& filePath, bool is64Bit);
void SaveResultsOffsets(const std::vector<std::pair<std::string, uintptr_t>>& results, const std::string& filePath);

#endif // UTILS_H
