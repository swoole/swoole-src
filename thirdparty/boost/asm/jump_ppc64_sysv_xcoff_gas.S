.align 2
.globl .jump_fcontext
.jump_fcontext:
    # reserve space on stack
    subi  1, 1, 328

    std  13, 152(1)  # save R13
    std  14, 160(1)  # save R14
    std  15, 168(1)  # save R15
    std  16, 176(1)  # save R16
    std  17, 184(1)  # save R17
    std  18, 192(1)  # save R18
    std  19, 200(1)  # save R19
    std  20, 208(1)  # save R20
    std  21, 216(1)  # save R21
    std  22, 224(1)  # save R22
    std  23, 232(1)  # save R23
    std  24, 240(1)  # save R24
    std  25, 248(1)  # save R25
    std  26, 256(1)  # save R26
    std  27, 264(1)  # save R27
    std  28, 272(1)  # save R28
    std  29, 280(1)  # save R29
    std  30, 288(1)  # save R30
    std  31, 296(1)  # save R31

    # save CR
    mfcr  0
    std  0, 304(1)
    # save LR
    mflr  0
    std  0, 312(1)
    # save LR as PC
    std  0, 320(1)

    # test if fpu env should be preserved
    cmpwi  7, 6, 0
    beq  7, label1

    stfd  14, 0(1)  # save F14
    stfd  15, 8(1)  # save F15
    stfd  16, 16(1)  # save F16
    stfd  17, 24(1)  # save F17
    stfd  18, 32(1)  # save F18
    stfd  19, 40(1)  # save F19
    stfd  20, 48(1)  # save F20
    stfd  21, 56(1)  # save F21
    stfd  22, 64(1)  # save F22
    stfd  23, 72(1)  # save F23
    stfd  24, 80(1)  # save F24
    stfd  25, 88(1)  # save F25
    stfd  26, 96(1)  # save F26
    stfd  27, 104(1)  # save F27
    stfd  28, 112(1)  # save F28
    stfd  29, 120(1)  # save F29
    stfd  30, 128(1)  # save F30
    stfd  31, 136(1)  # save F31
    mffs  0  # load FPSCR
    stfd  0, 144(1)  # save FPSCR

label1:
    # store RSP (pointing to context-data) in R3
    stw  1, 0(3)

    # restore RSP (pointing to context-data) from R4
    mr  1, 4

    # test if fpu env should be preserved
    cmpwi  7, 6, 0
    beq  7, label2

    lfd  14, 0(1)  # restore F14
    lfd  15, 8(1)  # restore F15
    lfd  16, 16(1)  # restore F16
    lfd  17, 24(1)  # restore F17
    lfd  18, 32(1)  # restore F18
    lfd  19, 40(1)  # restore F19
    lfd  20, 48(1)  # restore F20
    lfd  21, 56(1)  # restore F21
    lfd  22, 64(1)  # restore F22
    lfd  23, 72(1)  # restore F23
    lfd  24, 80(1)  # restore F24
    lfd  25, 88(1)  # restore F25
    lfd  26, 96(1)  # restore F26
    lfd  27, 104(1)  # restore F27
    lfd  28, 112(1)  # restore F28
    lfd  29, 120(1)  # restore F29
    lfd  30, 128(1)  # restore F30
    lfd  31, 136(1)  # restore F31
    lfd  0,  144(1)  # load FPSCR
    mtfsf  0xff, 0  # restore FPSCR

label2:
    ld  13, 152(1)  # restore R13
    ld  14, 160(1)  # restore R14
    ld  15, 168(1)  # restore R15
    ld  16, 176(1)  # restore R16
    ld  17, 184(1)  # restore R17
    ld  18, 192(1)  # restore R18
    ld  19, 200(1)  # restore R19
    ld  20, 208(1)  # restore R20
    ld  21, 216(1)  # restore R21
    ld  22, 224(1)  # restore R22
    ld  23, 232(1)  # restore R23
    ld  24, 240(1)  # restore R24
    ld  25, 248(1)  # restore R25
    ld  26, 256(1)  # restore R26
    ld  27, 264(1)  # restore R27
    ld  28, 272(1)  # restore R28
    ld  29, 280(1)  # restore R29
    ld  30, 288(1)  # restore R30
    ld  31, 296(1)  # restore R31

    # restore CR
    ld  0, 304(1)
    mtcr  0
    # restore LR
    ld  0, 312(1)
    mtlr  0

    # load PC
    ld  0, 320(1)
    # restore CTR
    mtctr  0

    # adjust stack
    addi  1, 1, 328

    # use third arg as return value after jump
    # use third arg as first arg in context function
    mr  3, 5

    # jump to context
    bctr
