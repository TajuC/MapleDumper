#include "includes.h"
int main() {
    auto ntFuncOpt = core::nt::LoadNtReadVirtualMemory();
    if (!ntFuncOpt) return 1;
    scan::Reader reader(*ntFuncOpt);
    const std::string exeDir = [] {
        char buf[MAX_PATH];
        GetModuleFileNameA(nullptr, buf, MAX_PATH);
        return std::string(buf).substr(0, std::string(buf).find_last_of("\\/"));
        }();
    const core::Config cfg = core::ReadConfig(exeDir + "\\config.ini");
    DWORD pid = cfg.byName
        ? proc::GetProcessIDByName("MapleStory.exe")
        : proc::GetProcessIDByClass("MapleStoryClass");
    HANDLE hProc = proc::OpenTargetProcess(pid);
    if (!hProc) return 1;

    const auto rawPatterns = io::ReadPatterns(exeDir + "\\patterns.txt", cfg.is64Bit);
    std::cout << "[+] Total patterns: " << rawPatterns.size() << "\n";
    std::vector<scan::PatternData> patterns;
    patterns.reserve(rawPatterns.size());
    for (auto& [name, data] : rawPatterns) {
        scan::PatternData p;
        p.name = name;
        p.size = data.size();
        p.bytes.resize(p.size);
        p.mask.resize(p.size);
        for (size_t i = 0; i < p.size; ++i) {
            if (data[i] == -1) { p.bytes[i] = 0; p.mask[i] = 0; }
            else { p.bytes[i] = uint8_t(data[i]); p.mask[i] = 0xFF; }
        }
        patterns.push_back(std::move(p));
    }

    auto regions = proc::GetMemoryRegions(hProc, true, "MapleStory.exe");
    std::vector<std::pair<std::string, uintptr_t>> results;
    std::mutex resultLock;
    std::atomic<size_t> regionIndex{ 0 };
    unsigned int numThreads = std::thread::hardware_concurrency();
    if (!numThreads) numThreads = 4;
    std::vector<std::thread> threads;
    threads.reserve(numThreads);

    for (unsigned int t = 0; t < numThreads; ++t) {
        threads.emplace_back([&] {
            while (true) {
                size_t idx = regionIndex.fetch_add(1);
                if (idx >= regions.size()) break;
                const auto& reg = regions[idx];
                const size_t padding = 32;
                const size_t bufferSize = reg.RegionSize + padding;
                std::vector<uint8_t> buffer(bufferSize, 0);
                size_t bytesRead = 0;
                if (!reader.Read(hProc, reinterpret_cast<LPCVOID>(reg.BaseAddress), buffer.data(), reg.RegionSize, bytesRead))
                    continue;
                for (auto& pat : patterns) {
                    if (bytesRead < pat.size) continue;
                    std::vector<uintptr_t> absMatches;
                    scan::FindAllMatchesWithBase(buffer.data(), bytesRead, pat.bytes, pat.mask, pat.size, reinterpret_cast<uintptr_t>(reg.BaseAddress), absMatches);
                    if (!absMatches.empty()) {
                        std::lock_guard<std::mutex> lg(resultLock);
                        std::cout << "[MATCHED] " << pat.name << " (" << absMatches.size() << " hits)\n";
                    }
                    for (uintptr_t matchAddr : absMatches) {
                        {
                            std::lock_guard<std::mutex> lg(resultLock);
                            results.emplace_back(pat.name, matchAddr);
                        }
                        if (pat.name.ends_with("_CALL")) {
                            uint32_t rel = 0; size_t r = 0;
                            if (reader.Read(hProc, reinterpret_cast<LPCVOID>(matchAddr + 1), &rel, sizeof(rel), r) && r == sizeof(rel)) {
                                uintptr_t target = matchAddr + 5 + static_cast<int32_t>(rel);
                                std::vector<uint8_t> callBuf(0x100);
                                size_t callRead = 0;
                                if (reader.Read(hProc, reinterpret_cast<LPCVOID>(target), callBuf.data(), callBuf.size(), callRead)) {
                                    uintptr_t resolved = 0;
                                    int callCount = 0;
                                    for (size_t i = 0; i + 5 <= callRead; ++i) {
                                        if (callBuf[i] == 0xE8) {
                                            uint32_t rel2 = *reinterpret_cast<uint32_t*>(&callBuf[i + 1]);
                                            resolved = target + i + 5 + static_cast<int32_t>(rel2);
                                            if (++callCount == 1) break;
                                        }
                                    }
                                    if (!resolved) resolved = target;
                                    std::lock_guard<std::mutex> lg2(resultLock);
                                    results.emplace_back(pat.name.substr(0, pat.name.size() - 5) + "_Base", resolved);
                                }
                            }
                        }
                        else if (pat.name.ends_with("_PTR")) {
                            uintptr_t addr = scan::ExtractPointerFromData(buffer.data() + (matchAddr - reinterpret_cast<uintptr_t>(reg.BaseAddress)), bytesRead - (matchAddr - reinterpret_cast<uintptr_t>(reg.BaseAddress)), matchAddr);
                            if (addr) {
                                std::lock_guard<std::mutex> lg2(resultLock);
                                results.emplace_back(pat.name.substr(0, pat.name.size() - 4) + "_Base", addr);
                            }
                        }
                        else if (pat.name.ends_with("_OFF")) {
                            uint32_t off = scan::TryExtractOffset(reader, hProc, matchAddr);
                            if (off) {
                                std::string clean = pat.name.substr(0, pat.name.size() - 4);
                                std::lock_guard<std::mutex> lg2(resultLock);
                                results.emplace_back(clean, static_cast<uintptr_t>(off));
                            }
                        }
                    }
                }
            }
            });
    }

    for (auto& th : threads) th.join();
    CloseHandle(hProc);

    std::unordered_map<std::string, int> summary;
    for (auto& pr : results) summary[pr.first]++;

    std::vector<std::string> found, notFound;
    for (auto& pr : rawPatterns) {
        std::string key = pr.first;
        if (key.ends_with("_PTR")) key = key.substr(0, key.size() - 4) + "_Base";
        else if (key.ends_with("_OFF")) key = key.substr(0, key.size() - 4);
        else if (key.ends_with("_CALL")) key = key.substr(0, key.size() - 5) + "_Base";
        if (summary.contains(key)) found.push_back(pr.first);
        else notFound.push_back(pr.first);
    }

    std::cout << "\n=== Pattern Hit Summary ===\n";
    std::cout << "\n[FOUND]\n";
    for (auto& name : found) std::cout << name << "\n";
    std::cout << "\n[NOTFOUND]\n";
    for (auto& name : notFound) std::cout << name << "\n";
    std::cout << "\nTotal FOUND: " << found.size() << "\n";
    std::cout << "Total NOTFOUND: " << notFound.size() << "\n";
    std::cout << "Total individual matches: " << results.size() << "\n";

    const std::string outPath = exeDir + "\\update.txt";
    if (cfg.ceTable) io::SaveResultsCEStyle(results, outPath);
    else io::SaveResultsText(results, outPath, cfg.is64Bit);

    if (cfg.generateOffsets) io::SaveResultsOffsets(results, exeDir + "\\offsets.h");

    return 0;
}
