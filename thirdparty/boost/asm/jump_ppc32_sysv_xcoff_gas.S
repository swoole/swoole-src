.globl .jump_fcontext
.globl  jump_fcontext[DS]
.align 2 
.csect	jump_fcontext[DS]
jump_fcontext:
  .long	.jump_fcontext
.jump_fcontext:
    # reserve space on stack
    subi 1, 1, 240

    stw 13, 152(1) # save R13
    stw 14, 156(1) # save R14
    stw 15, 160(1) # save R15
    stw 16, 164(1) # save R16
    stw 17, 168(1) # save R17
    stw 18, 172(1) # save R18
    stw 19, 176(1) # save R19
    stw 20, 180(1) # save R20
    stw 21, 184(1) # save R21
    stw 22, 188(1) # save R22
    stw 23, 192(1) # save R23
    stw 24, 196(1) # save R24
    stw 25, 200(1) # save R25
    stw 26, 204(1) # save R26
    stw 27, 208(1) # save R27
    stw 28, 212(1) # save R28
    stw 29, 216(1) # save R29
    stw 30, 220(1) # save R30
    stw 31, 224(1) # save R31

    # save CR
    mfcr 0
    stw 0, 228(1)
    # save LR
    mflr 0
    stw 0, 232(1)
    # save LR as PC
    stw 0, 236(1)

    # test if fpu env should be preserved
    cmpwi 7, 6, 0
    beq 7, label1

    stfd 14, 0(1) # save F14
    stfd 15, 8(1) # save F15
    stfd 16, 16(1) # save F16
    stfd 17, 24(1) # save F17
    stfd 18, 32(1) # save F18
    stfd 19, 40(1) # save F19
    stfd 20, 48(1) # save F20
    stfd 21, 56(1) # save F21
    stfd 22, 64(1) # save F22
    stfd 23, 72(1) # save F23
    stfd 24, 80(1) # save F24
    stfd 25, 88(1) # save F25
    stfd 26, 96(1) # save F26
    stfd 27, 104(1) # save F27
    stfd 28, 112(1) # save F28
    stfd 29, 120(1) # save F29
    stfd 30, 128(1) # save F30
    stfd 31, 136(1) # save F31
    mffs 0 # load FPSCR
    stfd 0, 144(1) # save FPSCR

label1:
    # store RSP (pointing to context-data) in R3
    stw 1, 0(3)

    # restore RSP (pointing to context-data) from R4
    mr 1, 4

    # test if fpu env should be preserved
    cmpwi 7, 6, 0
    beq 7, label2 

    lfd 14, 0(1) # restore F14
    lfd 15, 8(1) # restore F15
    lfd 16, 16(1) # restore F16
    lfd 17, 24(1) # restore F17
    lfd 18, 32(1) # restore F18
    lfd 19, 40(1) # restore F19
    lfd 20, 48(1) # restore F20
    lfd 21, 56(1) # restore F21
    lfd 22, 64(1) # restore F22
    lfd 23, 72(1) # restore F23
    lfd 24, 80(1) # restore F24
    lfd 25, 88(1) # restore F25
    lfd 26, 96(1) # restore F26
    lfd 27, 104(1) # restore F27
    lfd 28, 112(1) # restore F28
    lfd 29, 120(1) # restore F29
    lfd 30, 128(1) # restore F30
    lfd 31, 136(1) # restore F31
    lfd 0, 144(1) # load FPSCR
    mtfsf 0xff, 0 # restore FPSCR

label2:
    lwz 13, 152(1) # restore R13
    lwz 14, 156(1) # restore R14
    lwz 15, 160(1) # restore R15
    lwz 16, 164(1) # restore R16
    lwz 17, 168(1) # restore R17
    lwz 18, 172(1) # restore R18
    lwz 19, 176(1) # restore R19
    lwz 20, 180(1) # restore R20
    lwz 21, 184(1) # restore R21
    lwz 22, 188(1) # restore R22
    lwz 23, 192(1) # restore R23
    lwz 24, 196(1) # restore R24
    lwz 25, 200(1) # restore R25
    lwz 26, 204(1) # restore R26
    lwz 27, 208(1) # restore R27
    lwz 28, 212(1) # restore R28
    lwz 29, 216(1) # restore R29
    lwz 30, 220(1) # restore R30
    lwz 31, 224(1) # restore R31

    # restore CR
    lwz 0, 228(1)
    mtcr 0
    # restore LR
    lwz 0, 232(1)
    mtlr 0

    # load PC
    lwz 0, 236(1)
    # restore CTR
    mtctr 0

    # adjust stack
    addi 1, 1, 240

    # use third arg as return value after jump
    # use third arg as first arg in context function
    mr 3, 5

    # jump to context
    bctr
