#include "syscallsHelper.h"

// Função para verificar se o stub da função está limpo (não hookeado)
BOOL IsStubClean(PBYTE pStub) {
    if (pStub[0] == 0x4C &&
        pStub[1] == 0x8B &&
        pStub[2] == 0xD1 &&
        pStub[3] == 0xB8)
    {
        return TRUE; // Stub limpo, não hookeado
    }
    return FALSE;
}

// Função para obter o número de syscall de uma função específica
BOOL GetSyscallNumber(
    _In_ HMODULE hNtdll,
    _In_ LPCSTR FunctionName,
    _Out_ PDWORD SyscallNumber,
    _Out_ PRESOLUTION_METHOD ResolutionMethod
) {
    BOOL status = FALSE;

    BYTE* pFunction = (BYTE*)GetProcAddressPeb(hNtdll, FunctionName);

    if (!pFunction)
        return FALSE;

    // Percorre os primeiros bytes procurando:
    // 4C 8B D1        mov r10, rcx
    // B8 xx xx xx xx mov eax, SSN
    if (IsStubClean(pFunction)) {
        *SyscallNumber = *(DWORD*)&pFunction[4];
        *ResolutionMethod = RESOLUTION_STUBCLEAN;
        status = TRUE;
    }
    else {
        status = FALSE;
    }

    // Se o stub estiver hookeado, procura nos stubs vizinhos (acima)
    for (DWORD i = 1; i <= 32 && !status; i++) {
        PBYTE pNeighbor = pFunction + ((ULONG_PTR)i * SYSCALL_STUB_SIZE);
        if (IsStubClean(pNeighbor)) {
            *SyscallNumber = (*(DWORD*)&pNeighbor[4]) - (DWORD)i;
            *ResolutionMethod = RESOLUTION_HALOSGATE;
            status = TRUE;
        }
    }

    // Se o stub estiver hookeado, procura nos stubs vizinhos (abaixo)
    for (DWORD i = 1; i <= 32 && !status; i++) {
        PBYTE pNeighbor = pFunction - ((ULONG_PTR)i * SYSCALL_STUB_SIZE);
        if (IsStubClean(pNeighbor)) {
            *SyscallNumber = (*(DWORD*)&pNeighbor[4]) + (DWORD)i;
            *ResolutionMethod = RESOLUTION_HALOSGATE;
            status = TRUE;
        }
    }


    return status;
}

// Função para resolver todas as syscalls
VOID ResolveAllSyscalls(_In_ HMODULE hNtdll) {
    for (int i = 0; i < SYSCALL_COUNT; i++)
    {
        if (!
            GetSyscallNumber(
                hNtdll,
                Syscalls[i].Name,
                &Syscalls[i].SSN,
                &Syscalls[i].ResolutionMethod
            )
            )
        {
            return;
        }
    }
}

DWORD GetSSNFromSyscallTable(const char* Name) {
    for (int i = 0; i < SYSCALL_COUNT; i++)
    {
        if (strcmp(Syscalls[i].Name, Name) == 0)
            return Syscalls[i].SSN;
    }

    return 0;
}

// Função para exibir um relatório de como cada syscall foi resolvida
VOID PrintSyscallResolutionReport() {
    printf("\n========================================\n");
    printf("   SYSCALL RESOLUTION REPORT\n");
    printf("========================================\n\n");

    for (int i = 0; i < SYSCALL_COUNT; i++)
    {
        const char* methodStr = "";

        switch (Syscalls[i].ResolutionMethod)
        {
            case RESOLUTION_STUBCLEAN:
                methodStr = "StubClean (Direct)";
                break;
            case RESOLUTION_HALOSGATE:
                methodStr = "HalosGate (Neighbor Search)";
                break;
            default:
                methodStr = "Unknown";
                break;
        }

        printf("[%d] %-30s | SSN: 0x%08X | Method: %s\n",
            i + 1,
            Syscalls[i].Name,
            Syscalls[i].SSN,
            methodStr
        );
    }

    printf("\n========================================\n\n");
}