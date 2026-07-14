.CODE

EXTERN g_SyscallNumber:DWORD
EXTERN g_pSyscallInst:QWORD

; rcx->r10 for syscall ABI, eax=SSN, jmp to ntdll syscall;ret
SyscallTrampoline PROC
    mov r10, rcx
    mov eax, g_SyscallNumber
    jmp QWORD PTR [g_pSyscallInst]
SyscallTrampoline ENDP

END
