#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <cstring>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

class ProcessMemory {
public:
    ProcessMemory(int pid) : pid_(pid), handle_(-1) {
        std::string maps_path = "/proc/" + std::to_string(pid_) + "/maps";
        std::string mem_path = "/proc/" + std::to_string(pid_) + "/mem";

        handle_ = open(mem_path.c_str(), O_RDWR);
        if (handle_ == -1) {
            throw std::runtime_error("Failed to open process memory");
        }
    }

    ~ProcessMemory() {
        if (handle_ != -1) {
            close(handle_);
        }
    }

    template <typename T>
    T readMemory(long address) {
        T value;
        if (pread64(handle_, &value, sizeof(T), address) != sizeof(T)) {
            throw std::runtime_error("Failed to read memory");
        }
        return value;
    }

    template <typename T>
    void writeMemory(long address, T value) {
        if (pwrite64(handle_, &value, sizeof(T), address) != sizeof(T)) {
            throw std::runtime_error("Failed to write memory");
        }
    }

private:
    int pid_;
    int handle_;
};

class ProcessInfo {
public:
    static int getPID(const std::string& packageName) {
        std::unique_ptr<DIR, decltype(&closedir)> dir(opendir("/proc"), closedir);
        if (!dir) {
            throw std::runtime_error("Failed to open /proc directory");
        }

        while (dirent* entry = readdir(dir.get())) {
            int pid = atoi(entry->d_name);
            if (pid > 0) {
                std::string cmdlinePath = "/proc/" + std::to_string(pid) + "/cmdline";
                std::ifstream cmdlineFile(cmdlinePath);
                if (cmdlineFile) {
                    std::string cmdline;
                    std::getline(cmdlineFile, cmdline);
                    if (cmdline == packageName) {
                        return pid;
                    }
                }
            }
        }
        return -1;
    }

    static long getModuleAddress(int pid, const std::string& moduleName) {
        std::string mapsPath = "/proc/" + std::to_string(pid) + "/maps";
        std::ifstream mapsFile(mapsPath);
        if (!mapsFile) {
            throw std::runtime_error("Failed to open maps file");
        }

        std::string line;
        while (std::getline(mapsFile, line)) {
            if (line.find(moduleName) != std::string::npos) {
                size_t dashPos = line.find('-');
                if (dashPos != std::string::npos) {
                    return std::stol(line.substr(0, dashPos), nullptr, 16);
                }
            }
        }
        return 0;
    }
};

int main() {
    try {
        int pid = ProcessInfo::getPID("com.umonistudio.tile");
        if (pid == -1) {
            std::cerr << "Process not found" << std::endl;
            return 1;
        }

        std::cout << "PID: " << pid << std::endl;

        ProcessMemory memory(pid);
        long moduleAddress = ProcessInfo::getModuleAddress(pid, "libtarget.so");
        if (moduleAddress == 0) {
            std::cerr << "Module not found" << std::endl;
            return 1;
        }

        std::cout << "Module address: " << std::hex << moduleAddress << std::endl;

        // Example: Read a float value from memory
        float value = memory.readMemory<float>(moduleAddress + 0x1000);
        std::cout << "Read value: " << value << std::endl;

        // Example: Write a float value to memory
        memory.writeMemory<float>(moduleAddress + 0x1000, 3.14f);

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}