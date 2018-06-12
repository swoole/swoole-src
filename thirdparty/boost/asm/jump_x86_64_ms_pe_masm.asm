
;           Copyright Oliver Kowalke 2009.
;  Distributed under the Boost Software License, Version 1.0.
;     (See accompanying file LICENSE_1_0.txt or copy at
;           http://www.boost.org/LICENSE_1_0.txt)

;  ----------------------------------------------------------------------------------
;  |    0    |    1    |                                                            |
;  ----------------------------------------------------------------------------------
;  |   0x0   |   0x4   |                                                            |
;  ----------------------------------------------------------------------------------
;  |    <indicator>    |                                                            |
;  ----------------------------------------------------------------------------------
;  ----------------------------------------------------------------------------------
;  |    2    |    3    |    4     |    5    |    6    |    7    |    8    |    9    |
;  ----------------------------------------------------------------------------------
;  |   0x8   |   0xc   |   0x10   |   0x14  |   0x18  |   0x1c  |   0x20  |   0x24  |
;  ----------------------------------------------------------------------------------
;  |                          SEE registers (XMM6-XMM15)                            |
;  ----------------------------------------------------------------------------------
;  ----------------------------------------------------------------------------------
;  |   10    |   11    |    12    |    13   |    14   |    15   |    16   |    17   |
;  ----------------------------------------------------------------------------------
;  |   0x28  |  0x2c   |   0x30   |   0x34  |   0x38  |   0x3c  |   0x40  |   0x44  |
;  ----------------------------------------------------------------------------------
;  |                          SEE registers (XMM6-XMM15)                            |
;  ----------------------------------------------------------------------------------
;  ----------------------------------------------------------------------------------
;  |    18   |    19   |    20   |    21    |    22   |    23   |    24   |    25   |
;  ----------------------------------------------------------------------------------
;  |   0x48  |   0x4c  |   0x50  |   0x54   |   0x58  |   0x5c  |  0x60   |   0x64  |
;  ----------------------------------------------------------------------------------
;  |                          SEE registers (XMM6-XMM15)                            |
;  ----------------------------------------------------------------------------------
;  ----------------------------------------------------------------------------------
;  |    26   |    27   |    28    |   29    |    30   |    31   |    32   |    33   |
;  ----------------------------------------------------------------------------------
;  |   0x68  |   0x6c  |   0x70   |   0x74  |   0x78  |   0x7c  |   0x80  |   0x84  |
;  ----------------------------------------------------------------------------------
;  |                          SEE registers (XMM6-XMM15)                            |
;  ----------------------------------------------------------------------------------
;  ----------------------------------------------------------------------------------
;  |    34    |   35   |    36    |    37   |    38   |    39   |    40   |    41   |
;  ----------------------------------------------------------------------------------
;  |   0x88   |  0x8c  |   0x90   |   0x94  |   0x98  |   0x9c  |   0xa0  |   0xa4  |
;  ----------------------------------------------------------------------------------
;  |                          SEE registers (XMM6-XMM15)                            |
;  ----------------------------------------------------------------------------------
;  ----------------------------------------------------------------------------------
;  |    42   |    43   |    44    |    45   |    46   |    47   |    48   |    49   |
;  ----------------------------------------------------------------------------------
;  |   0xa8  |   0xac  |   0xb0   |   0xb4  |   0xb8  |   0xbc  |   0xc0  |   0xc4  |
;  ----------------------------------------------------------------------------------
;  | fc_mxcsr|fc_x87_cw|     <alignment>    |      fbr_strg     |      fc_dealloc   |
;  ----------------------------------------------------------------------------------
;  ----------------------------------------------------------------------------------
;  |    50   |   51    |    52    |    53   |    54   |    55   |    56   |    57   |
;  ----------------------------------------------------------------------------------
;  |   0xc8  |  0xcc   |   0xd0   |   0xd4  |   0xd8  |   0xdc  |   0xe0  |   0xe4  |
;  ----------------------------------------------------------------------------------
;  |      limit        |       base         |      R12          |        R13        |
;  ----------------------------------------------------------------------------------
;  ----------------------------------------------------------------------------------
;  |    58   |    59   |    60   |    61    |    62   |    63   |    64   |    65   |
;  ----------------------------------------------------------------------------------
;  |   0xe8  |   0xec  |   0xf0  |   0xf4   |   0xf8  |   0xfc  |  0x100  |  0x104  |
;  ----------------------------------------------------------------------------------
;  |        R14        |        R15         |       RDI         |       RSI         |
;  ----------------------------------------------------------------------------------
;  ----------------------------------------------------------------------------------
;  |    66   |   67    |    68    |   69    |    70   |  71     |    72   |    73   |
;  ----------------------------------------------------------------------------------
;  |  0x108  |  0x10c  |  0x110   |  0x114  |  0x118  |  0x11c  |  0x120  |  0x124  |
;  ----------------------------------------------------------------------------------
;  |        RBX        |         RBP        |        RIP        |       EXIT        |
;  ----------------------------------------------------------------------------------

.code

jump_fcontext PROC BOOST_CONTEXT_EXPORT FRAME
    .endprolog

    push  rbp  ; save RBP
    push  rbx  ; save RBX
    push  rsi  ; save RSI
    push  rdi  ; save RDI
    push  r15  ; save R15
    push  r14  ; save R14
    push  r13  ; save R13
    push  r12  ; save R12

    ; load NT_TIB
    mov  r10,  gs:[030h]
    ; save current stack base
    mov  rax,  [r10+08h]
    push  rax
    ; save current stack limit
    mov  rax, [r10+010h]
    push  rax
    ; save current deallocation stack
    mov  rax, [r10+01478h]
    push  rax
    ; save fiber local storage
    mov  rax, [r10+018h]
    push  rax

    ; prepare stack for FPU
    lea rsp, [rsp-0a8h]

    ; test for flag preserve_fpu
    test  r9, r9
    je  nxt1

    ; save MMX control- and status-word
    stmxcsr  [rsp+0a0h]
    ; save x87 control-word
    fnstcw  [rsp+0a4h]

    ; save XMM storage
    movaps  [rsp], xmm6
    movaps  [rsp+010h], xmm7
    movaps  [rsp+020h], xmm8
    movaps  [rsp+030h], xmm9
    movaps  [rsp+040h], xmm10
    movaps  [rsp+050h], xmm11
    movaps  [rsp+060h], xmm12
    movaps  [rsp+070h], xmm13
    movaps  [rsp+080h], xmm14
    movaps  [rsp+090h], xmm15

nxt1:
    ; set R10 to zero
    xor  r10, r10
    ; set indicator
    push  r10

    ; store RSP (pointing to context-data) in RCX
    mov  [rcx], rsp

    ; restore RSP (pointing to context-data) from RDX
    mov  rsp, rdx

    ; load indicator
    pop  r10

    ; test for flag preserve_fpu
    test  r9, r9
    je  nxt2

    ; restore MMX control- and status-word
    ldmxcsr  [rsp+0a0h]
    ; save x87 control-word
    fldcw   [rsp+0a4h]

    ; restore XMM storage
    movaps  xmm6, [rsp]
    movaps  xmm7, [rsp+010h]
    movaps  xmm8, [rsp+020h]
    movaps  xmm9, [rsp+030h]
    movaps  xmm10, [rsp+040h]
    movaps  xmm11, [rsp+050h]
    movaps  xmm12, [rsp+060h]
    movaps  xmm13, [rsp+070h]
    movaps  xmm14, [rsp+080h]
    movaps  xmm15, [rsp+090h]

nxt2:
    ; set offset of stack
    mov  rcx, 0a8h

    ; test for indicator
    test  r10, r10
    je  nxt3

    add  rcx, 08h

nxt3:
    ; prepare stack for FPU
    lea rsp, [rsp+rcx]

    ; load NT_TIB
    mov  r10, gs:[030h]
    ; restore fiber local storage
    pop  rax
    mov  [r10+018h], rax
    ; restore deallocation stack
    pop  rax
    mov  [r10+01478h], rax
    ; restore stack limit
    pop  rax
    mov  [r10+010h], rax
    ; restore stack base
    pop  rax
    mov  [r10+08h], rax

    pop  r12  ; restore R12
    pop  r13  ; restore R13
    pop  r14  ; restore R14
    pop  r15  ; restore R15
    pop  rdi  ; restore RDI
    pop  rsi  ; restore RSI
    pop  rbx  ; restore RBX
    pop  rbp  ; restore RBP

    ; restore return-address
    pop  r10

    ; use third arg as return-value after jump
    mov  rax, r8
    ; use third arg as first arg in context function
    mov  rcx, r8

    ; indirect jump to context
    jmp  r10
jump_fcontext ENDP
END
