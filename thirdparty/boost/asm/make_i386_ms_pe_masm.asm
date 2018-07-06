
;           Copyright Oliver Kowalke 2009.
;  Distributed under the Boost Software License, Version 1.0.
;     (See accompanying file LICENSE_1_0.txt or copy at
;           http://www.boost.org/LICENSE_1_0.txt)

;  ---------------------------------------------------------------------------------
;  |    0    |    1    |    2    |    3    |    4    |    5    |    6    |    7    |
;  ---------------------------------------------------------------------------------
;  |    0h   |   04h   |   08h   |   0ch   |   010h  |   014h  |   018h  |   01ch  |
;  ---------------------------------------------------------------------------------
;  | fc_mxcsr|fc_x87_cw| fc_strg |fc_deallo|  limit  |   base  |  fc_seh |   EDI   |
;  ---------------------------------------------------------------------------------
;  ---------------------------------------------------------------------------------
;  |    8    |    9    |   10    |    11   |    12   |    13   |    14   |    15   |
;  ---------------------------------------------------------------------------------
;  |   020h  |  024h   |  028h   |   02ch  |   030h  |   034h  |   038h  |   03ch  |
;  ---------------------------------------------------------------------------------
;  |   ESI   |   EBX   |   EBP   |   EIP   |   EXIT  |         | SEH NXT |SEH HNDLR|
;  ---------------------------------------------------------------------------------

.386
.XMM
.model flat, c
; standard C library function
_exit PROTO, value:SDWORD
.code

make_fcontext PROC BOOST_CONTEXT_EXPORT
    ; first arg of make_fcontext() == top of context-stack
    mov  eax, [esp+04h]

    ; reserve space for first argument of context-function
    ; EAX might already point to a 16byte border
    lea  eax, [eax-08h]

    ; shift address in EAX to lower 16 byte boundary
    and  eax, -16

    ; reserve space for context-data on context-stack
    ; size for fc_mxcsr .. EIP + return-address for context-function
    ; on context-function entry: (ESP -0x4) % 8 == 0
    ; additional space is required for SEH
    lea  eax, [eax-03ch]

    ; first arg of make_fcontext() == top of context-stack
    mov  ecx, [esp+04h]
    ; save top address of context stack as 'base'
    mov  [eax+014h], ecx
    ; second arg of make_fcontext() == size of context-stack
    mov  edx, [esp+08h]
    ; negate stack size for LEA instruction (== substraction)
    neg  edx
    ; compute bottom address of context stack (limit)
    lea  ecx, [ecx+edx]
    ; save bottom address of context-stack as 'limit'
    mov  [eax+010h], ecx
    ; save bottom address of context-stack as 'dealloction stack'
    mov  [eax+0ch], ecx

    ; third arg of make_fcontext() == address of context-function
    mov  ecx, [esp+0ch]
    mov  [eax+02ch], ecx

    ; save MMX control- and status-word
    stmxcsr  [eax]
    ; save x87 control-word
    fnstcw  [eax+04h]

    ; compute abs address of label finish
    mov  ecx, finish
    ; save address of finish as return-address for context-function
    ; will be entered after context-function returns
    mov  [eax+030h], ecx

    ; traverse current seh chain to get the last exception handler installed by Windows
    ; note that on Windows Server 2008 and 2008 R2, SEHOP is activated by default
    ; the exception handler chain is tested for the presence of ntdll.dll!FinalExceptionHandler
    ; at its end by RaiseException all seh-handlers are disregarded if not present and the
    ; program is aborted
    assume  fs:nothing
    ; load NT_TIB into ECX
    mov  ecx, fs:[0h]
    assume  fs:error

walk:
    ; load 'next' member of current SEH into EDX
    mov  edx, [ecx]
    ; test if 'next' of current SEH is last (== 0xffffffff)
    inc  edx
    jz  found
    dec  edx
    ; exchange content; ECX contains address of next SEH
    xchg edx, ecx
    ; inspect next SEH
    jmp  walk

found:
    ; load 'handler' member of SEH == address of last SEH handler installed by Windows
    mov  ecx, [ecx+04h]
    ; save address in ECX as SEH handler for context
    mov  [eax+03ch], ecx
    ; set ECX to -1
    mov  ecx, 0ffffffffh
    ; save ECX as next SEH item
    mov  [eax+038h], ecx
    ; load address of next SEH item
    lea  ecx, [eax+038h]
    ; save next SEH
    mov  [eax+018h], ecx

    ret ; return pointer to context-data

finish:
    ; exit code is zero
    xor  eax, eax
    mov  [esp], eax
    ; exit application
    call  _exit
    hlt
make_fcontext ENDP
END
