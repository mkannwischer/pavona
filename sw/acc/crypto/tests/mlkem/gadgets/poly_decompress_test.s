/* Copyright zeroRISC Inc. */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */

#define NB_POLY 512

.section .text.start

main:
    /* All-zero register. */
    bn.xor w31, w31, w31

    /* MOD <= R | Q; sw0 (w16) <= MOD. */
    addi    x4, x0, 0
    la      x5, modulus_bn
    bn.lid  x4++, 0(x5)
    bn.rshi w0, w31, w0 >> 240
    la      x5, modulus_inv
    bn.lid  x4, 0(x5)
    bn.or   w0, w0, w1 << 32
    bn.wsrw mod, w0
    bn.wsrr w16, mod

    /* dmem[r_dv4] <= poly_decompress(dmem[x_dv4]), k != 4 path (dv = 4). */
    la   x10, x_dv4
    la   x11, r_dv4
    addi x12, x0, 2 /* k */
    jal  x1, poly_decompress

    /* dmem[r_dv5] <= poly_decompress(dmem[x_dv5]), k = 4 path (dv = 5). */
    la   x10, x_dv5
    la   x11, r_dv5
    addi x12, x0, 4 /* k */
    jal  x1, poly_decompress

    ecall

.data
.balign 32
r_dv4:
    .zero NB_POLY
r_dv5:
    .zero NB_POLY
