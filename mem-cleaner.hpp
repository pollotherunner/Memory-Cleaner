#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <random>
#include <ctime>

class c_mem_cleaner
{
public:

    void clear_string_by_procname(std::wstring process_name, std::wstring find) {

        HANDLE proc_handle = open_proc_by_name(process_name);
        scan_strings(find, proc_handle);
        std::wstring replace = gen_random_string();

        for (uintptr_t addreses : founded_adresses)
        {
            WriteProcessMemory(proc_handle, (LPVOID)addreses, &replace.c_str()[0], (replace.size() + 1) * sizeof(wchar_t), NULL);
        }
    }

    void clear_string_by_pid(DWORD pid, std::wstring find) {

        HANDLE proc_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        scan_strings(find, proc_handle);
        std::wstring replace = gen_random_string();

        for (uintptr_t addreses : founded_adresses)
        {
            WriteProcessMemory(proc_handle, (LPVOID)addreses, &replace.c_str()[0], (replace.size() + 1) * sizeof(wchar_t), NULL);
        }
    }

private:

    std::vector<uintptr_t> founded_adresses;

    void scan_strings(std::wstring stringtofind, HANDLE hproc)
    {
        char* currentmemorypage = 0;
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        MEMORY_BASIC_INFORMATION info;

        while (currentmemorypage < si.lpMaximumApplicationAddress)
        {
            if (VirtualQueryEx(hproc, currentmemorypage, &info, sizeof(info)) == sizeof(info))
            {
                if (info.State == MEM_COMMIT && info.Protect == PAGE_READWRITE)
                {
                    std::vector<char> buffer(info.RegionSize);

                    if (ReadProcessMemory(hproc, currentmemorypage, &buffer[0], info.RegionSize, NULL))
                    {
                        for (size_t begin = 0; begin < info.RegionSize; ++begin)
                        {
                            if (buffer[begin] == stringtofind[0])
                            {
                                std::wstring stringbuffer;

                                for (size_t copy = 0; copy < stringtofind.size() && (begin + copy) < info.RegionSize; ++copy)
                                {
                                    stringbuffer += buffer[begin + copy];
                                }

                                if (stringtofind == stringbuffer)
                                {
                                    founded_adresses.push_back(reinterpret_cast<uintptr_t>(currentmemorypage) + begin);
                                }
                            }
                        }
                    }
                }
            }

            currentmemorypage += info.RegionSize;
        }
    }

    std::wstring gen_random_string(size_t length = 5) {
        const std::wstring characters = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        std::random_device rd;
        std::mt19937 generator(rd());
        std::uniform_int_distribution<> distrib(0, characters.size() - 1);

        std::wstring result;
        for (size_t i = 0; i < length; ++i) {
            result += characters[distrib(generator)];
        }

        return result;
    }

    HANDLE open_proc_by_name(std::wstring name) {

        PROCESSENTRY32W pe32w;
        pe32w.dwSize = sizeof(PROCESSENTRY32W);
        HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot_handle == INVALID_HANDLE_VALUE) return nullptr;

        if (Process32FirstW(snapshot_handle, &pe32w)) {
            do {
                if (name == pe32w.szExeFile) {
                    DWORD pid = pe32w.th32ProcessID;
                    CloseHandle(snapshot_handle);
                    return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
                }
            } while (Process32NextW(snapshot_handle, &pe32w));
        }

        CloseHandle(snapshot_handle);
        return nullptr;
    }
};

inline c_mem_cleaner g_mem_cleaner;
