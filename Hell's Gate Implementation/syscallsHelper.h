#pragma once

#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <cstring>

#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define SYSCALL_STUB_SIZE 0x20

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
}

// Estruturas necessárias para a função NtCreateThreadEx
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

//Estruturas para realizar pebwalking
typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
} PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

// Estrutura para armazenar informações sobre syscalls
enum
{
	SYSCALL_ALLOCATE,
	SYSCALL_WRITEPROCESS,
	SYSCALL_CREATEREMOTETHREAD,
	SYSCALL_WAITFOR_SINGLEOBJECT,
	SYSCALL_CLOSE,
	SYSCALL_COUNT
};

// Enumeração para indicar como a syscall foi resolvida
enum RESOLUTION_METHOD
{
	RESOLUTION_NONE = 0,
	RESOLUTION_STUBCLEAN = 1,
	RESOLUTION_HALOSGATE = 2
};

typedef RESOLUTION_METHOD* PRESOLUTION_METHOD;

struct SYSCALL_ENTRY
{
	const char* Name;
	DWORD SSN;
	RESOLUTION_METHOD ResolutionMethod;
};

extern SYSCALL_ENTRY Syscalls[SYSCALL_COUNT];

// Função para verificar se o stub da função está limpo (não hookeado)
BOOL IsStubClean(PBYTE pStub);

// Função para obter o número de syscall de uma função específica
BOOL GetSyscallNumber(
    _In_ HMODULE hNtdll,
    _In_ LPCSTR FunctionName,
    _Out_ PDWORD SyscallNumber,
    _Out_ PRESOLUTION_METHOD ResolutionMethod
);

// Função para resolver todas as syscalls
VOID ResolveAllSyscalls(_In_ HMODULE hNtdll);

DWORD GetSSNFromSyscallTable(const char* Name);

// Função para exibir um relatório de como cada syscall foi resolvida
VOID PrintSyscallResolutionReport();

//PEB Walking functions

HMODULE GetModuleHandlePeb(LPCWSTR moduleName);

FARPROC GetProcAddressPeb(HMODULE hModule, LPCSTR procName);