/* Copyright zeroRISC Inc. */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Runtime population of the masked ML-DSA broadcast constant vectors from
 * mldsa_params.
 */

.equ x1, ra
.equ x5, t0
.equ x6, t1
.equ x7, t2
.equ x10, a0
.equ x11, a1
.equ x28, t3

#define MLDSA_PARAM_K_OFFSET 0
#define MLDSA_PARAM_GAMMA1_MINUS_BETA_OFFSET 16
#define MLDSA_PARAM_GAMMA2_OFFSET 28
#define MLDSA_PARAM_GAMMA2_MINUS_BETA_OFFSET 32

#ifdef HARDENED
/**
 * Populate the single-symbol masked broadcast vectors from mldsa_params.
 * c_z/c_r need all 8 lanes written for DMEM integrity (secboundcheck reads
 * only lane 0).
 *
 * clobbered registers: a0, a1, t0-t3
 */
.globl _setup_masked_vectors
_setup_masked_vectors:
    la   a0, mldsa_params

    /* gamma2_vec_const = broadcast(GAMMA2) */
    lw   t0, MLDSA_PARAM_GAMMA2_OFFSET(a0)
    la   a1, gamma2_vec_const
    loopi 8, 2
        sw   t0, 0(a1)
        addi a1, a1, 4
    endloop

    /* lambda0_z_vec = broadcast(GAMMA1_MINUS_BETA - 1) */
    lw   t0, MLDSA_PARAM_GAMMA1_MINUS_BETA_OFFSET(a0)
    addi t0, t0, -1
    la   a1, lambda0_z_vec
    loopi 8, 2
        sw   t0, 0(a1)
        addi a1, a1, 4
    endloop

    /* lambda0_r_vec = broadcast(GAMMA2_MINUS_BETA - 1) */
    lw   t0, MLDSA_PARAM_GAMMA2_MINUS_BETA_OFFSET(a0)
    addi t0, t0, -1
    la   a1, lambda0_r_vec
    loopi 8, 2
        sw   t0, 0(a1)
        addi a1, a1, 4
    endloop

    /* c_z_const = broadcast((1<<24) - 2*(GAMMA1_MINUS_BETA - 1) - 1) */
    lw   t0, MLDSA_PARAM_GAMMA1_MINUS_BETA_OFFSET(a0)
    addi t0, t0, -1
    slli t0, t0, 1
    li   t1, 0x1000000
    sub  t1, t1, t0
    addi t1, t1, -1
    la   a1, c_z_const
    loopi 8, 2
        sw   t1, 0(a1)
        addi a1, a1, 4
    endloop

    /* c_r_const = broadcast((1<<24) - 2*(GAMMA2_MINUS_BETA - 1) - 1) */
    lw   t0, MLDSA_PARAM_GAMMA2_MINUS_BETA_OFFSET(a0)
    addi t0, t0, -1
    slli t0, t0, 1
    li   t1, 0x1000000
    sub  t1, t1, t0
    addi t1, t1, -1
    la   a1, c_r_const
    loopi 8, 2
        sw   t1, 0(a1)
        addi a1, a1, 4
    endloop

    /* K selects the remaining vectors: gamma1 (2^17 for K==4 else 2^19),
     * polyz unpack mask, and eta (4 for K==6 else 2). */
    lw   t2, MLDSA_PARAM_K_OFFSET(a0)

    li   t0, 524288
    li   t3, 4
    bne  t2, t3, _smv_gamma_done
    li   t0, 131072
_smv_gamma_done:
    la   a1, gamma1_vec_const
    loopi 8, 2
        sw   t0, 0(a1)
        addi a1, a1, 4
    endloop

    li   t0, 0xfffff
    li   t3, 4
    bne  t2, t3, _smv_polyz
    li   t0, 0x3ffff
_smv_polyz:
    la   a1, polyz_unpack_mask
    loopi 8, 2
        sw   t0, 0(a1)
        addi a1, a1, 4
    endloop

    li   t0, 2
    li   t3, 6
    bne  t2, t3, _smv_eta
    li   t0, 4
_smv_eta:
    la   a1, eta
    loopi 8, 2
        sw   t0, 0(a1)
        addi a1, a1, 4
    endloop

    ret
#endif
