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
*******************************************************************/

.file	"make_i386_ms_pe_gas.asm"
.text
.p2align 4,,15
.globl	_make_fcontext
.def	_make_fcontext;	.scl	2;	.type	32;	.endef
_make_fcontext:
    /* first arg of make_fcontext() == top of context-stack */
    movl  0x04(%esp), %eax

    /* reserve space for first argument of context-function */
    /* EAX might already point to a 16byte border */
    leal  -0x08(%eax), %eax

    /* shift address in EAX to lower 16 byte boundary */
    andl  $-16, %eax

    /* reserve space for context-data on context-stack */
    /* size for fc_mxcsr .. EIP + return-address for context-function */
    /* on context-function entry: (ESP -0x4) % 8 == 0 */
    /* additional space is required for SEH */
    leal  -0x3c(%eax), %eax

    /* first arg of make_fcontext() == top of context-stack */
    movl  0x04(%esp), %ecx
    /* save top address of context stack as 'base' */
    movl  %ecx, 0x14(%eax)
    /* second arg of make_fcontext() == size of context-stack */
    movl  0x08(%esp), %edx
    /* negate stack size for LEA instruction (== substraction) */
    negl  %edx
    /* compute bottom address of context stack (limit) */
    leal  (%ecx,%edx), %ecx
    /* save bottom address of context-stack as 'limit' */
    movl  %ecx, 0x10(%eax)
    /* save bottom address of context-stack as 'dealloction stack' */
    movl  %ecx, 0xc(%eax)

    /* third arg of make_fcontext() == address of context-function */
    movl  0xc(%esp), %ecx
    movl  %ecx, 0x2c(%eax)

    /* save MMX control- and status-word */
    stmxcsr  (%eax)
    /* save x87 control-word */
    fnstcw  0x04(%eax)

    /* compute abs address of label finish */
    movl  $finish, %ecx
    /* save address of finish as return-address for context-function */
    /* will be entered after context-function returns */
    movl  %ecx, 0x30(%eax)

    /* traverse current seh chain to get the last exception handler installed by Windows */
    /* note that on Windows Server 2008 and 2008 R2, SEHOP is activated by default */
    /* the exception handler chain is tested for the presence of ntdll.dll!FinalExceptionHandler */
    /* at its end by RaiseException all seh andlers are disregarded if not present and the */
    /* program is aborted */
    /* load NT_TIB into ECX */
    movl  %fs:(0x0), %ecx

walk:
    /* load 'next' member of current SEH into EDX */
    movl  (%ecx), %edx
    /* test if 'next' of current SEH is last (== 0xffffffff) */
    incl  %edx
    jz  found
    decl  %edx
    /* exchange content; ECX contains address of next SEH */
    xchgl  %ecx, %edx
    /* inspect next SEH */
    jmp  walk

found:
    /* load 'handler' member of SEH == address of last SEH handler installed by Windows */
    movl  0x04(%ecx), %ecx
    /* save address in ECX as SEH handler for context */
    movl  %ecx, 0x3c(%eax)
    /* set ECX to -1 */
    movl  $0xffffffff, %ecx
    /* save ECX as next SEH item */
    movl  %ecx, 0x38(%eax)
    /* load address of next SEH item */
    leal  0x38(%eax), %ecx
    /* save next SEH */
    movl  %ecx, 0x18(%eax)

    /* return pointer to context-data */
    ret

finish:
    /* ESP points to same address as ESP on entry of context function + 0x4 */
    xorl  %eax, %eax
    /* exit code is zero */
    movl  %eax, (%esp)
    /* exit application */
    call  __exit
    hlt

.def	__exit;	.scl	2;	.type	32;	.endef  /* standard C library function */
