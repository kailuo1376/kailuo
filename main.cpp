#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <malloc.h>
#include <math.h>
#include <stdint.h>
#include <stdbool.h>

typedef char PACKAGENAME;

int getPID(const char *packageName) {
    DIR *dir;
    FILE *fp;
    char filename[64];
    char cmdline[64];
    struct dirent *entry;
    dir = opendir("/proc");
    if (!dir) return -1;

    while ((entry = readdir(dir)) != NULL) {
        int id = atoi(entry->d_name);
        if (id > 0) {
            snprintf(filename, sizeof(filename), "/proc/%d/cmdline", id);
            fp = fopen(filename, "r");
            if (fp) {
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);
                if (strncmp(cmdline, packageName, strlen(packageName)) == 0) {
                    closedir(dir);
                    return id;
                }
            }
        }
    }
    closedir(dir);
    return -1;
}

long int getXa(int pid, const char *module_name) {
    FILE *fp;
    long addr = 0;
    char line[1024];
    snprintf(line, sizeof(line), "/proc/%d/maps", pid);
    fp = fopen(line, "r");
    if (fp) {
        char *pch = strtok(line, "-");
        if (pch) {
            addr = strtoul(pch, NULL, 16);
            if (addr == 0x8000) addr = 0;
        }
        fclose(fp);
    }
    return addr;
}

long getbss(int pid, const char *module_name) {
    FILE *fp;
    long addr = 0;
    char line[1024];
    snprintf(line, sizeof(line), "/proc/%d/maps", pid);
    fp = fopen(line, "r");
    bool is_module = false;
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name) && strstr(line, "[anon:.bss]")) {
                sscanf(line, "%lx", &addr);
                break;
            }
        }
        fclose(fp);
    }
    return addr;
}

uintptr_t getCd(int pid, const char *module_name) {
    FILE *fp;
    uintptr_t addr = 0;
    char line[1024];
    snprintf(line, sizeof(line), "/proc/%d/maps", pid);
    fp = fopen(line, "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name) && strstr(line, "rw-p")) {
                char *pch = strtok(line, "-");
                if (pch) {
                    addr = strtoul(pch, NULL, 16);
                    break;
                }
            }
        }
        fclose(fp);
    }
    return addr;
}

long int getCb(int pid, const char *module_name) {
    FILE *fp;
    long addr = 0;
    char line[1024];
    snprintf(line, sizeof(line), "/proc/%d/maps", pid);
    fp = fopen(line, "r");
    bool is_module = false;
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name) && strstr(line, "rw-p")) {
                is_module = true;
            }
            if (is_module && strstr(line, "[anon:.bss]")) {
                sscanf(line, "%lx", &addr);
                break;
            }
        }
        fclose(fp);
    }
    return addr;
}

long int handle;

float getF(long int addr) {
    float var = 0;
    memcpy(&var, (void*)addr, sizeof(float));
    return var;
}

int getD(long int addr) {
    int var = 0;
    memcpy(&var, (void*)addr, sizeof(int));
    return var;
}

long int lsp32(long int addr) {
    long int var = 0;
    memcpy(&var, (void*)addr, sizeof(int));
    return var;
}

inline int setint(long int addr, int value) {
    memcpy((void*)addr, &value, sizeof(int));
    return 0;
}

int 修改D类(long int addr, int value) {
    memcpy((void*)addr, &value, sizeof(int));
    return 0;
}

long int lsp64(long int addr)
{
	long int var = 0;
	pread64(handle, &var, 8, addr);
	return var;
}

float 修改F类(long int addr, float value) {
    memcpy((void*)addr, &value, sizeof(float));
    return value;
}

int main() {
    const char *packageName = "com.LanPiaoPiao.PlantsVsZombiesRH.zzb";
    const char *module_name = "libil2cpp.so";

    // 获取进程 PID
    int PID = getPID(packageName);
    if (PID == -1) {
        printf("无法找到进程: %s\n", packageName);
        return 1;
    }
    printf("进程 PID: %d\n", PID);

    // 打开进程内存
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", PID);
    int handle = open(mem_path, O_RDWR);
    if (handle == -1) {
        printf("无法打开进程内存: %s\n", mem_path);
        return 1;
    }

    // 获取模块基址
    long int base_addr = getCd(PID, module_name);
    if (base_addr == 0) {
        printf("无法找到模块基址: %s\n", module_name);
        close(handle);
        return 1;
    }
    printf("模块基址: 0x%lx\n", base_addr);

    // 指针链解析
    long int addresses[6] = {0}; // 用于存储每一步的地址
    addresses[0] = base_addr + 0x40CB8; // 第一步：基址 + 偏移
    long int addr1 = lsp64(addresses[0]);
    addresses[1] = addr1;
    if (addr1 == 0) {
        printf("无法正确跳转到第一步地址: 0x%lx\n", addresses[0]);
        close(handle);
        return 1;
    }

    addresses[2] = addr1 + 0xFC0; // 第二步：上级指针 + 偏移
    long int addr2 = lsp64(addresses[2]);
    addresses[3] = addr2;
    if (addr2 == 0) {
        printf("无法正确跳转到第二步地址: 0x%lx\n", addresses[2]);
        close(handle);
        return 1;
    }

    addresses[4] = addr2 + 0x1B0; // 第三步：上级指针 + 偏移
    long int addr3 = lsp64(addresses[4]);
    addresses[5] = addr3;
    if (addr3 == 0) {
        printf("无法正确跳转到第三步地址: 0x%lx\n", addresses[4]);
        close(handle);
        return 1;
    }

    // 最终地址
    long int final_addr = addr3 + 0xAC;
    printf("最终地址: 0x%lx\n", final_addr);

    // 读取最终地址的值
    int value = getD(final_addr);
    printf("最终地址的值: %d\n", value);

    // 关闭进程内存
    close(handle);

    return 0;
}