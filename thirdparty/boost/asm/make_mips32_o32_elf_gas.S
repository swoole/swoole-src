/*
            Copyright Oliver Kowalke 2009.
   Distributed under the Boost Software License, Version 1.0.
      (See accompanying file LICENSE_1_0.txt or copy at
          http://www.boost.org/LICENSE_1_0.txt)
*/

/*******************************************************
 *                                                     *
 *  -------------------------------------------------  *
 *  |  0  |  1  |  2  |  3  |  4  |  5  |  6  |  7  |  *
 *  -------------------------------------------------  *
 *  |  0  |  4  |  8  |  12 |  16 |  20 |  24 |  28 |  *
 *  -------------------------------------------------  *
 *  |    F20    |    F22    |    F24    |    F26    |  *
 *  -------------------------------------------------  *
 *  -------------------------------------------------  *
 *  |  8  |  9  |  10 |  11 |  12 |  13 |  14 |  15 |  *
 *  -------------------------------------------------  *
 *  |  32 |  36 |  40 |  44 |  48 |  52 |  56 |  60 |  *
 *  -------------------------------------------------  *
 *  |    F28    |    F30    |  S0 |  S1 |  S2 |  S3 |  *
 *  -------------------------------------------------  *
 *  -------------------------------------------------  *
 *  |  16 |  17 |  18 |  19 |  20 |  21 |  22 |     |  *
 *  -------------------------------------------------  *
 *  |  64 |  68 |  72 |  76 |  80 |  84 |  88 |     |  *
 *  -------------------------------------------------  *
 *  |  S4 |  S5 |  S6 |  S7 |  FP |  RA |  PC |     |  *
 *  -------------------------------------------------  *
 *                                                     *
 * *****************************************************/

.text
.globl make_fcontext
.align 2
.type make_fcontext,@function
.ent make_fcontext
make_fcontext:
#ifdef __PIC__
.set    noreorder
.cpload $t9
.set    reorder
#endif
    # first arg of make_fcontext() == top address of context-stack
    move $v0, $a0

    # shift address in A0 to lower 16 byte boundary
    move $v1, $v0
    li $v0, -16 # 0xfffffffffffffff0
    and $v0, $v1, $v0

    # reserve space for context-data on context-stack
    # including 48 byte of shadow space (sp % 16 == 0)
    addiu $v0, $v0, -140

    # third arg of make_fcontext() == address of context-function
    sw  $a2, 88($v0)
    # save global pointer in context-data
    # S0 will contain address of global pointer
    sw  $gp, 48($v0)

    # compute abs address of label finish
    la  $t9, finish
    # save address of finish as return-address for context-function
    # will be entered after context-function returns
    sw  $t9, 84($v0)

    jr  $ra # return pointer to context-data

finish:
    # allocate stack space (contains shadow space for subroutines)
    addiu  $sp, $sp, -32
    # save return address
    sw  $ra, 28($sp)

    # restore GP (global pointer)
    move  $gp, $s0
    # exit code is zero
    move  $a0, $zero
    # address of exit
    lw  $t9, %call16(_exit)($gp)
    # exit application
    jalr  $t9
.end make_fcontext
.size make_fcontext, .-make_fcontext

/* Mark that we don't need executable stack.  */
.section .note.GNU-stack,"",%progbits
