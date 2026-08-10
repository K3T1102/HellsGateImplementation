.data
wSystemCall DWORD 0

.code

HellsGate PROC

    mov wSystemCall, ecx
    ret

HellsGate ENDP


HellDescent PROC

    mov r10, rcx
    mov eax, wSystemCall
    syscall
    ret

HellDescent ENDP

END