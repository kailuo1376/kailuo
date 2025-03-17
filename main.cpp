#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

class ProcessMemory {
public:
    ProcessMemory(int pid) {
        char mem_path[64];
        snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
        handle = open(mem_path, O_RDWR);
        if (handle == -1) {
            throw std::runtime_error("无法打开进程内存");
        }
    }

    ~ProcessMemory() {
        if (handle != -1) {
            close(handle);
        }
    }

    template<typename T>
    T read(uintptr_t addr) {
        T value;
        if (pread64(handle, &value, sizeof(T), addr) != sizeof(T)) {
            throw std::runtime_error("读取内存失败");
        }
        return value;
    }

    template<typename T>
    void write(uintptr_t addr, T value) {
        if (pwrite64(handle, &value, sizeof(T), addr) != sizeof(T)) {
            throw std::runtime_error("写入内存失败");
        }
    }

private:
    int handle;
};

int getPID(const std::string& packageName) {
    DIR* dir = opendir("/proc");
    if (!dir) return -1;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        int id = atoi(entry->d_name);
        if (id > 0) {
            char filename[64];
            snprintf(filename, sizeof(filename), "/proc/%d/cmdline", id);
            std::ifstream cmdline(filename);
            if (cmdline) {
                std::string cmdlineContent;
                std::getline(cmdline, cmdlineContent);
                if (cmdlineContent.find(packageName) == 0) {
                    closedir(dir);
                    return id;
                }
            }
        }
    }
    closedir(dir);
    return -1;
}

uintptr_t getModuleBaseAddress(int pid, const std::string& moduleName) {
    char mapsPath[64];
    snprintf(mapsPath, sizeof(mapsPath), "/proc/%d/maps", pid);
    std::ifstream maps(mapsPath);
    if (!maps) {
        throw std::runtime_error("无法打开maps文件");
    }

    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(moduleName) != std::string::npos && line.find("rw-p") != std::string::npos) {
            size_t dashPos = line.find('-');
            if (dashPos != std::string::npos) {
                return std::stoul(line.substr(0, dashPos), nullptr, 16);
            }
        }
    }
    return 0;
}

int main() {
    const std::string packageName = "com.LanPiaoPiao.PlantsVsZombiesRH.zzb";
    const std::string moduleName = "libil2cpp.so";

    try {
        // 获取进程 PID
        int pid = getPID(packageName);
        if (pid == -1) {
            std::cerr << "无法找到进程: " << packageName << std::endl;
            return 1;
        }
        std::cout << "进程 PID: " << pid << std::endl;

        // 打开进程内存
        ProcessMemory processMemory(pid);

        // 获取模块基址
        uintptr_t baseAddr = getModuleBaseAddress(pid, moduleName);
        if (baseAddr == 0) {
            std::cerr << "无法找到模块基址: " << moduleName << std::endl;
            return 1;
        }
        std::cout << "模块基址: 0x" << std::hex << baseAddr << std::dec << std::endl;

        // 指针链解析
        uintptr_t finalAddr = baseAddr + 0x40CB8;
        finalAddr = processMemory.read<uintptr_t>(finalAddr) + 0xFC0;
        finalAddr = processMemory.read<uintptr_t>(finalAddr) + 0x1B0;
        finalAddr += 0xAC;

        std::cout << "最终地址: 0x" << std::hex << finalAddr << std::dec << std::endl;

        // 读取最终地址的值
        int value = processMemory.read<int>(finalAddr);
        std::cout << "最终地址的值: " << value << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}