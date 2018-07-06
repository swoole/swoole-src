/*
            Copyright Oliver Kowalke 2009.
            Copyright Thomas Sailer 2013.
   Distributed under the Boost Software License, Version 1.0.
      (See accompanying file LICENSE_1_0.txt or copy at
            http://www.boost.org/LICENSE_1_0.txt)
*/

/********************************************************************
  ---------------------------------------------------------------------------------
  |    0    |    1    |    2    |    3    |    4    |    5    |    6    |    7    |
  ---------------------------------------------------------------------------------
  |    0h   |   04h   |   08h   |   0ch   |   010h  |   014h  |   018h  |   01ch  |
  ---------------------------------------------------------------------------------
  | fc_mxcsr|fc_x87_cw| fc_strg |fc_deallo|  limit  |   base  |  fc_seh |   EDI   |
  ---------------------------------------------------------------------------------
  ---------------------------------------------------------------------------------
  |    8    |    9    |   10    |    11   |    12   |    13   |    14   |    15   |
  ---------------------------------------------------------------------------------
  |   020h  |  024h   |  028h   |   02ch  |   030h  |   034h  |   038h  |   03ch  |
  ---------------------------------------------------------------------------------
  |   ESI   |   EBX   |   EBP   |   EIP   |   EXIT  |         | SEH NXT |SEH HNDLR|
  ---------------------------------------------------------------------------------
* *****************************************************************/

.file	"jump_i386_ms_pe_gas.asm"
.text
.p2align 4,,15
.globl	_jump_fcontext
.def	_jump_fcontext;	.scl	2;	.type	32;	.endef
_jump_fcontext:
    /* fourth arg of jump_fcontext() == flag indicating preserving FPU */
    movl  0x10(%esp), %ecx

    pushl  %ebp  /* save EBP */
    pushl  %ebx  /* save EBX */
    pushl  %esi  /* save ESI */
    pushl  %edi  /* save EDI */

    /* load NT_TIB */
    movl  %fs:(0x18), %edx

    /* load current SEH exception list */
    movl  (%edx), %eax
    push  %eax

    /* load current stack base */
    movl  0x04(%edx), %eax
    push  %eax

    /* load current stack limit */
    movl  0x08(%edx), %eax
    push  %eax
    
    /* load current dealloction stack */
    movl  0xe0c(%edx), %eax
    push  %eax
    
    /* load fiber local storage */
    movl  0x10(%edx), %eax
    push  %eax

    /* prepare stack for FPU */
    leal  -0x08(%esp), %esp

    /* test for flag preserve_fpu */
    testl  %ecx, %ecx 
    je  1f

    /* save MMX control word */
    stmxcsr  (%esp)
    /* save x87 control word */
    fnstcw  0x04(%esp)

1:
    /* first arg of jump_fcontext() == context jumping from */
    movl  0x30(%esp), %eax

    /* store ESP (pointing to context-data) in EAX */
    movl  %esp, (%eax)

    /* second arg of jump_fcontext() == context jumping to */
    movl  0x34(%esp), %edx

    /* third arg of jump_fcontext() == value to be returned after jump */
    movl  0x38(%esp), %eax

    /* restore ESP (pointing to context-data) from EDX */
    movl  %edx, %esp

    /* test for flag preserve_fpu */
    testl  %ecx, %ecx
    je  2f

    /* restore MMX control- and status-word */
    ldmxcsr  (%esp)
    /* restore x87 control-word */
    fldcw  0x04(%esp)

2:
    /* prepare stack for FPU */
    leal  0x08(%esp), %esp

    /* load NT_TIB into ECX */
    movl  %fs:(0x18), %edx

    /* restore fiber local storage */
    popl  %ecx
    movl  %ecx, 0x10(%edx)

    /* restore current deallocation stack */
    popl  %ecx
    movl  %ecx, 0xe0c(%edx)

    /* restore current stack limit */
    popl  %ecx
    movl  %ecx, 0x08(%edx)

    /* restore current stack base */
    popl  %ecx
    movl  %ecx, 0x04(%edx)

    /* restore current SEH exception list */
    popl  %ecx
    movl  %ecx, (%edx)

    popl  %edi  /* save EDI */
    popl  %esi  /* save ESI */
    popl  %ebx  /* save EBX */
    popl  %ebp  /* save EBP */

    /* restore return-address */
    popl  %edx

    /* use value in EAX as return-value after jump */
    /* use value in EAX as first arg in context function */
    movl  %eax, 0x04(%esp)

    /* indirect jump to context */
    jmp  *%edx
