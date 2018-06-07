;/*
;            Copyright Oliver Kowalke 2009.
;   Distributed under the Boost Software License, Version 1.0.
;      (See accompanying file LICENSE_1_0.txt or copy at
;          http://www.boost.org/LICENSE_1_0.txt)
;*/

; *******************************************************
; *                                                     *
; *  -------------------------------------------------  *
; *  |  0  |  1  |  2  |  3  |  4  |  5  |  6  |  7  |  *
; *  -------------------------------------------------  *
; *  | 0x0 | 0x4 | 0x8 | 0xc | 0x10| 0x14| 0x18| 0x1c|  *
; *  -------------------------------------------------  *
; *  | s16 | s17 | s18 | s19 | s20 | s21 | s22 | s23 |  *
; *  -------------------------------------------------  *
; *  -------------------------------------------------  *
; *  |  8  |  9  |  10 |  11 |  12 |  13 |  14 |  15 |  *
; *  -------------------------------------------------  *
; *  | 0x20| 0x24| 0x28| 0x2c| 0x30| 0x34| 0x38| 0x3c|  *
; *  -------------------------------------------------  *
; *  | s24 | s25 | s26 | s27 | s28 | s29 | s30 | s31 |  *
; *  -------------------------------------------------  *
; *  -------------------------------------------------  *
; *  |  16 |  17 |  18 |  19 |  20 |  21 |  22 |  23 |  *
; *  -------------------------------------------------  *
; *  | 0x40| 0x44| 0x48| 0x4c| 0x50| 0x54| 0x58| 0x5c|  *
; *  -------------------------------------------------  *
; *  |deall|limit| base|  v1 |  v2 |  v3 |  v4 |  v5 |  *
; *  -------------------------------------------------  *
; *  -------------------------------------------------  *
; *  |  24 |  25 |  26 |  27 |  28 |                 |  *
; *  -------------------------------------------------  *
; *  | 0x60| 0x64| 0x68| 0x6c| 0x70|                 |  *
; *  -------------------------------------------------  *
; *  |  v6 |  v7 |  v8 |  lr |  pc |                 |  *
; *  -------------------------------------------------  *
; *                                                     *
; *******************************************************

    AREA |.text|, CODE
    ALIGN 4
    EXPORT jump_fcontext

jump_fcontext PROC
    @ save LR as PC
    push {lr}
    @ save V1-V8,LR
    push {v1-v8,lr}

    @ prepare stack for FPU
    sub  sp, sp, #0x4c

    @ test if fpu env should be preserved
    cmp  a4, #0
    beq  1f

    @ save S16-S31
    vstmia  sp, {d8-d15}

1:
    ; load TIB to save/restore thread size and limit.
    ; we do not need preserve CPU flag and can use it's arg register
    mrc     p15, #0, v1, c13, c0, #2

    ; save current stack base
    ldr  a5, [v1,#0x04]
    str  a5, [sp,#0x48]
    ; save current stack limit
    ldr  a5, [v1,#0x08]
    str  a5, [sp,#0x44]
    ; save current deallocation stack
    ldr  a5, [v1,#0xe0c]
    str  a5, [sp,#0x40]

    @ store RSP (pointing to context-data) in A1
    str  sp, [a1]

    @ restore RSP (pointing to context-data) from A2
    mov  sp, a2

    @ test if fpu env should be preserved
    cmp  a4, #0
    beq  2f

    @ restore S16-S31
    vldmia  sp, {d8-d15}

2:
    ; restore stack base
    ldr  a5, [sp,#0x48]
    str  a5, [v1,#0x04]
    ; restore stack limit
    ldr  a5, [sp,#0x44]
    str  a5, [v1,#0x08]
    ; restore deallocation stack
    ldr  a5, [sp,#0x40]
    str  a5, [v1,#0xe0c]

    @ prepare stack for FPU
    add  sp, sp, #0x4c

    ; use third arg as return value after jump
    ; and as first arg in context function
    mov  a1, a3

    @ restore v1-V8,LR
    pop  {v1-v8,lr}
    pop  {pc}

    ENDP
    END
