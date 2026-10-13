/* Copyright zeroRISC Inc. */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */

/* Runs the Jasmin mul256 on the operands of sw/acc/code-snippets/mul256.s. */

.section .text.start
  la    x2, operand1
  bn.ld w0, 0(x2)
  la    x2, operand2
  bn.ld w1, 0(x2)
  jal   x1, mul256
  ecall

.section .data
.balign 32
operand1:
  .quad 0x61a5a8d66985591e
  .quad 0x49de6d75d0221f41
  .quad 0xf6835831c3623f41
  .quad 0xfbc20c8e4ba684f2

operand2:
  .quad 0x5de6ee4dbd0f089d
  .quad 0x60f39da06db956ec
  .quad 0x1a1c98e116948392
  .quad 0x10ad673384d81d98
