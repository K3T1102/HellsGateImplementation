#include "syscallsHelper.h"

HMODULE GetModuleHandlePeb(LPCWSTR moduleName) {
    PPEB pPeb = (PPEB)__readgsqword(0x60);

    if (!pPeb || !pPeb->Ldr)
        return nullptr;

    PPEB_LDR_DATA pLdr = pPeb->Ldr;

    LIST_ENTRY* head = &pLdr->InLoadOrderModuleList;
    LIST_ENTRY* current = head->Flink;

    while (current != head)
    {
        auto entry = CONTAINING_RECORD(current, _LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (_wcsicmp(entry->BaseDllName.Buffer, moduleName) == 0)
        {
            return (HMODULE)entry->DllBase;
        }

        current = current->Flink;
    };

    return nullptr;
}

FARPROC GetProcAddressPeb(HMODULE hModule, LPCSTR procName) {
    if (!hModule) return nullptr;

    auto dosHeader = (PIMAGE_DOS_HEADER)hModule;
    auto ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    auto exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    if (!exportDirRVA) return nullptr;

    auto exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDirRVA);
    auto names = (DWORD*)((BYTE*)hModule + exportDir->AddressOfNames);
    auto ordinals = (WORD*)((BYTE*)hModule + exportDir->AddressOfNameOrdinals);
    auto functions = (DWORD*)((BYTE*)hModule + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
    {
        LPCSTR name = (LPCSTR)((BYTE*)hModule + names[i]);
        if (_stricmp(name, procName) == 0)
        {
            WORD ordinal = ordinals[i];
            DWORD funcRVA = functions[ordinal];
            return (FARPROC)((BYTE*)hModule + funcRVA);
        }
    }

    return nullptr;
}