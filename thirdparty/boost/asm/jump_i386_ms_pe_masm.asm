
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
.code

jump_fcontext PROC BOOST_CONTEXT_EXPORT
    ; fourth arg of jump_fcontext() == flag indicating preserving FPU
    mov  ecx, [esp+010h]

    push  ebp  ; save EBP 
    push  ebx  ; save EBX 
    push  esi  ; save ESI 
    push  edi  ; save EDI 

    assume  fs:nothing
    ; load NT_TIB into ECX
    mov  edx, fs:[018h]
    assume  fs:error

    ; load current SEH exception list
    mov  eax, [edx]
    push  eax

    ; load current stack base
    mov  eax, [edx+04h]
    push  eax

    ; load current stack limit
    mov  eax, [edx+08h]
    push  eax

    ; load current deallocation stack
    mov  eax, [edx+0e0ch]
    push  eax

    ; load fiber local storage
    mov  eax, [edx+010h]
    push  eax

    ; prepare stack for FPU
    lea  esp, [esp-08h]

    ; test for flag preserve_fpu
    test  ecx, ecx
    je  nxt1

    ; save MMX control- and status-word
    stmxcsr  [esp]
    ; save x87 control-word
    fnstcw  [esp+04h]

nxt1:
    ; first arg of jump_fcontext() == context jumping from
    mov  eax, [esp+030h]

    ; store ESP (pointing to context-data) in EAX
    mov  [eax], esp

    ; second arg of jump_fcontext() == context jumping to
    mov  edx, [esp+034h]

    ; third arg of jump_fcontext() == value to be returned after jump
    mov  eax, [esp+038h]

    ; restore ESP (pointing to context-data) from EDX
    mov  esp, edx

    ; test for flag preserve_fpu
    test  ecx, ecx
    je  nxt2

    ; restore MMX control- and status-word
    ldmxcsr  [esp]
    ; restore x87 control-word
    fldcw  [esp+04h]

nxt2:
    ; prepare stack for FPU
    lea  esp, [esp+08h]

    assume  fs:nothing
    ; load NT_TIB into ECX
    mov  edx, fs:[018h]
    assume  fs:error

    ; restore fiber local storage
    pop  ecx
    mov  [edx+010h], ecx

    ; restore current deallocation stack
    pop  ecx
    mov  [edx+0e0ch], ecx

    ; restore current stack limit
    pop  ecx
    mov  [edx+08h], ecx

    ; restore current stack base
    pop  ecx
    mov  [edx+04h], ecx

    ; restore current SEH exception list
    pop  ecx
    mov  [edx], ecx

    pop  edi  ; save EDI 
    pop  esi  ; save ESI 
    pop  ebx  ; save EBX 
    pop  ebp  ; save EBP 

    ; restore return-address
    pop  edx

    ; use value in EAX as return-value after jump
    ; use value in EAX as first arg in context function
    mov  [esp+04h], eax

    ; indirect jump to context
    jmp  edx
jump_fcontext ENDP
END
