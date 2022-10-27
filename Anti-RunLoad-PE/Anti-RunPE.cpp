#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <sstream>
#include <string>
#include <psapi.h>
#include <thread>
// Structs

enum detects {
    // {Категория детекта}_{Название дететка}_{Уровень опасности детекта}
    // Уровни опасностей: Low, Moderate, Considerable, High, Extreme
    NO_DETECT = 0x0,
    Memory_RWXMemoryDetected_Low = 0x1,
    Memory_ImageBaseMismath_High = 0x2
};
//

// API
HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
using NtQueryInformationProcessProt = NTSTATUS(WINAPI*) (HANDLE, int, PVOID, ULONG, PULONG);
using NtSuspendProcessProt = NTSTATUS(WINAPI*)(HANDLE hProcess);
void* NtSuspendProcessAdr = (void*)GetProcAddress(hNtDll, "NtSuspendProcess");
void* NtQueryInformationProcessAdr = (void*)GetProcAddress(hNtDll, "NtQueryInformationProcess");
NtQueryInformationProcessProt NtQueryInformationProcessP = (NtQueryInformationProcessProt)NtQueryInformationProcessAdr;
NtSuspendProcessProt NtSuspendProcess = (NtSuspendProcessProt)NtSuspendProcessAdr;
//

// Global Variables
char title[] = "Anti-RunLoad-PE";
//

PPEB getPEB(HANDLE hProcess) {
    // Используем NtQueryInformationProcess (NTAPI) функцию для получения PEB адреса в памяти процесса
    PROCESS_BASIC_INFORMATION pbi;
    NtQueryInformationProcessP(hProcess, ProcessBasicInformation, &pbi, sizeof pbi, 0);
    return pbi.PebBaseAddress;
}

// Много фейк детектов
BOOL RWXMemory_Detector(HANDLE hProcess, DWORD dwImageBase) {
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQueryEx(hProcess, PVOID(dwImageBase), &mbi, sizeof mbi);
    // Выполняем цикл до конца секций
    do {
        if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)
            return 1;
        DWORD dwNextSectionAdr = (DWORD)mbi.BaseAddress + mbi.RegionSize;
        VirtualQueryEx(hProcess, PVOID(dwNextSectionAdr), &mbi, sizeof mbi);
    } while (mbi.AllocationBase != 0);
    return 0;
}

BOOL ImageBaseMismath_Detector(HANDLE hProcess, DWORD dwPEBImageBase, DWORD PebAddress) {
    DWORD otherImageBaseAdr = PebAddress - 0x1000 + 0x10;
    DWORD otherImageBase;
    DWORD dwSize;
    ReadProcessMemory(hProcess, PVOID(otherImageBaseAdr), &otherImageBase, 4, &dwSize);
    if (dwPEBImageBase != otherImageBase && dwSize == 4) {
        return 1;
    }
    return 0;
}

DWORD checkProcessW(HANDLE hProcess) {
    DWORD ImageBaseOfProcess;
    PPEB PEBInfoOfProcess = getPEB(hProcess); // Получаем адрес до PEB памяти процесса
    DWORD PEB_ImageBaseAdr = (DWORD)PEBInfoOfProcess + 8; // PEB + 8 = адрес до ImageBase процесса
    
    ReadProcessMemory(hProcess, PVOID(PEB_ImageBaseAdr), &ImageBaseOfProcess, 4, 0); // Читаем память по адресу PEB + 8 и выставляем значение в DWORD ImageBaseOfProcess ( DWORD хранит в себе 4 байта )
    
    if (ImageBaseMismath_Detector(hProcess, ImageBaseOfProcess, DWORD(PEBInfoOfProcess))) {
        return Memory_ImageBaseMismath_High;
    }

    return 0;
}

void antiResume(HANDLE hProcess) {
    while (true) {
        Sleep(5);
        NtSuspendProcess(hProcess);
    }
}

void checkProcessA(DWORD PID) {
    if (PID) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, PID);
        std::ostringstream stream;
        stream << PID;
        std::string strPID = stream.str();
        DWORD ret = checkProcessW(hProcess);
        switch (ret)
        {
        case Memory_ImageBaseMismath_High:
            TerminateProcess(hProcess, 0);
            std::string text = "Memory_ImageBaseMismath_High was detection in process " + strPID + ".\nProcess has terminated";
            MessageBoxA(0, text.c_str(), title, 0x00000010L);
        }
        CloseHandle(hProcess);
    }
}

int main()
{
    while (true) {
        Sleep(150);
        DWORD dwProcesses[1024];
        DWORD count;
        EnumProcesses(dwProcesses, sizeof dwProcesses, &count);
        count = count / sizeof(DWORD);
        for (int i = 0; i < count; i++) {
            checkProcessA(dwProcesses[i]);
        }
    }
}