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
    EXPORT make_fcontext
    IMPORT _exit

make_fcontext PROC
    ; first arg of make_fcontext() == top of context-stack
    ; save top of context-stack (base) A4
    mov  a4, a1

    ; shift address in A1 to lower 16 byte boundary
    bic  a1, a1, #0x0f

    ; reserve space for context-data on context-stack
    sub  a1, a1, #0x74

    ; save top address of context_stack as 'base'
    str  a4, [a1,#0x48]
    ; second arg of make_fcontext() == size of context-stack
    ; compute bottom address of context-stack (limit)
    sub  a4, a4, a2
    ; save bottom address of context-stack as 'limit'
    str  a4, [a1,#0x44]
    ; save bottom address of context-stack as 'dealloction stack'
    str  a4, [a1,#0x40]

    ; third arg of make_fcontext() == address of context-function
    str  a3, [a1,#0x70]

    ; compute abs address of label finish
    adr  a2, finish
    ; save address of finish as return-address for context-function
    ; will be entered after context-function returns
    str  a2, [a1,#0x6c]

    bx  lr ; return pointer to context-data

finish
    ; exit code is zero
    mov  a1, #0
    ; exit application
    bl  _exit

    ENDP
    END
