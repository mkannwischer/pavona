/* Copyright zeroRISC Inc. */
/* Modified by Authors of "Towards ML-KEM & ML-DSA on OpenTitan" (https://eprint.iacr.org/2024/1192). */
/* Copyright "Towards ML-KEM & ML-DSA on OpenTitan" Authors. */
/* Modified by Ruben Niederhagen and Hoang Nguyen Hien Pham - authors of */
/* "Improving ML-KEM & ML-DSA on OpenTitan - Efficient Multiplication Vector Instructions for OTBN" */
/* (https://eprint.iacr.org/2025/2028). */
/* Copyright Ruben Niederhagen and Hoang Nguyen Hien Pham. */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */

.text

#define SEEDBYTES 32
#define CRHBYTES 64
#define TRBYTES 64
#define RNDBYTES 32
#define N 256
#define Q 8380417
#define D 13

/* Worst-case (ML-DSA-87) polyvec sizes for static buffers. */
#define POLYVECK_BYTES 8192
#define POLYVECL_BYTES 7168

/* Offsets into the mldsa_params struct (in mldsa_consts.s). */
#define MLDSA_PARAM_K_OFFSET 0
#define MLDSA_PARAM_L_OFFSET 4
#define MLDSA_PARAM_TAU_OFFSET 8
#define MLDSA_PARAM_OMEGA_OFFSET 12
#define MLDSA_PARAM_GAMMA1_MINUS_BETA_OFFSET 16
#define MLDSA_PARAM_POLYW1_PACKEDBYTES_OFFSET 20
#define MLDSA_PARAM_CRYPTO_PUBLICKEYBYTES_OFFSET 24
#define MLDSA_PARAM_GAMMA2_OFFSET 28
#define MLDSA_PARAM_GAMMA2_MINUS_BETA_OFFSET 32
#define MLDSA_PARAM_SK_S2_OFFSET_OFFSET 36
#define MLDSA_PARAM_SK_T0_OFFSET_OFFSET 40
#define MLDSA_PARAM_CRYPTO_BYTES_OFFSET 44

/* Register aliases */
.equ x2, sp
.equ x3, fp

.equ x5, t0
#define t1 x6
.equ x7, t2

.equ x8, s0
.equ x9, s1

.equ x10, a0
.equ x11, a1

.equ x12, a2
.equ x13, a3
.equ x14, a4
.equ x15, a5
.equ x16, a6
.equ x17, a7

.equ x18, s2
.equ x19, s3
.equ x20, s4
.equ x21, s5
.equ x22, s6
.equ x23, s7
.equ x24, s8
.equ x25, s9
.equ x26, s10
.equ x27, s11

.equ x28, t3
.equ x29, t4
.equ x30, t5
.equ x31, t6

.equ w31, bn0

/* Index of the Keccak command special register. */
#define KECCAK_CFG_REG 0x7d9
/* Config to start a SHAKE-128 operation. */
#define SHAKE128_CFG 0x2
/* Config to start a SHAKE-256 operation. */
#define SHAKE256_CFG 0xA
/* Config to start a SHA3_256 operation. */
#define SHA3_256_CFG 0x8
/* Config to start a SHA3_512 operation. */
#define SHA3_512_CFG 0x10


/**
 * Dilithium Sign
 *
 * Returns: 0 on success
 *
 * All input DMEM buffers must be 32-byte aligned and initialized up to the
 * next 32B boundary so wide-reads succeed.
 *
 * @param[in]  x10: *sig (destination pointer)
 * @param[in]  dmem[mu]: externally computed mu (64B)
 * @param[in]  dmem[sk]: secret key, 32B aligned
 * @param[in]  dmem[rnd]: signature randomization value (32B)
 * @param[out] x10: 0 (success)
 * @param[out] x11: siglen
 * @param[out] dmem[*sig]: signature
 *
 */
.global crypto_sign_signature_internal
.type crypto_sign_signature_internal, @function
crypto_sign_signature_internal:
#ifdef HARDENED
#define NSHARES 2
#define W0_POLYS 8
#define W0_SHARE_STRIDE 8192
#define W0_POLYVEC w0_polyvec_shares

    /* Masked gadgets use sp for stack frames; init it once on entry. */
    la sp, mask_stack_end
    /* External-mu mode (FIPS 204 Algorithm 7, ML-DSA.Sign_internal):
     * caller pre-hashes the message and provides mu in dmem[mu].  The
     * msg/ctx buffers and the initial SHAKE-256 over tr||ctxlen||ctx||msg
     * are gone -- saves ~2.4 KiB DMEM and one Keccak invocation. */

    /* Initialize a SHAKE256 operation. */
    addi  a1, x0, SEEDBYTES
    addi  a1, a1, RNDBYTES
    addi  a1, a1, CRHBYTES
    slli  t0, a1, 5
    addi  t0, t0, SHAKE256_CFG
    /* Set masked-digest bit (bit 20) of kmac_cfg so K stays shared
     * across the SHAKE256 and rho' is produced as 2 shares. */
    addi  t1, x0, 1
    slli  t1, t1, 20
    add   t0, t0, t1
    csrrw x0, KECCAK_CFG_REG, t0

    /* Refresh and absorb the Boolean shares of K. */
    la      t0, K_shares
    bn.wsrr w2, urnd
    bn.xor  w0, w0, w0            /* Whitening */
    bn.lid  x0, 0(t0)
    bn.xor  w0, w0, w2
    bn.wsrw kmac_msg, w0
    bn.xor  w0, w0, w0            /* Whitening */
    bn.lid  x0, 32(t0)
    bn.xor  w0, w0, w2
    bn.wsrw kmac_msg1, w0

    /* Send rnd as (rnd, 0): public input trivially shared on share 0. */
    la     t0, rnd
    bn.lid x0, 0(t0)
    bn.wsrw kmac_msg, w0
    bn.xor w0, w0, w0
    bn.wsrw kmac_msg1, w0

    /* Send mu (64B = 2 chunks) as (mu, 0). */
    la     t0, mu
    bn.lid x0, 0(t0)
    bn.wsrw kmac_msg, w0
    bn.xor w0, w0, w0
    bn.wsrw kmac_msg1, w0
    la     t0, mu
    bn.lid x0, 32(t0)
    bn.wsrw kmac_msg, w0
    bn.xor w0, w0, w0
    bn.wsrw kmac_msg1, w0

    /* Read 64B masked digest into sign_gamma1_buf[0..127] in the
     * share-major chunked layout that masked_poly_uniform_gamma_1
     * expects: share 0 chunks at [0,32], share 1 chunks at [64,96]. */
    la      a0, sign_gamma1_buf
    bn.wsrr w0, kmac_digest
    bn.sid  x0, 0(a0)
    bn.xor  w0, w0, w0             /* Whitening */
    bn.wsrr w0, kmac_digest1
    bn.sid  x0, 64(a0)
    bn.xor  w0, w0, w0             /* Whitening */
    bn.wsrr w0, kmac_digest
    bn.sid  x0, 32(a0)
    bn.xor  w0, w0, w0             /* Whitening */
    bn.wsrr w0, kmac_digest1
    bn.sid  x0, 96(a0)

    /* Finish the SHAKE-256 operation. */

    /* Prepare modulus */
    #define mod_x2 w22
    bn.wsrr   w16, 0x0 /* w16 = MOD = R | Q */
    bn.shv.8S mod_x2, w16 << 1 /* mod_x2 = 2*R | 2*Q */

    li s11, 0 /* nonce */

    jal  x1, sign_attempt
    ret

/* sign_attempt: rejection-retry body.  Computes w, w0/w1 + c~, c,
 * z (z-loop), h (hint loop); restarts in place on rejection.  Inputs
 * are taken from caller-set state (sign_gamma1_buf, sk, etc.); on
 * success returns a0 = 0, a1 = CRYPTO_BYTES. */
.global sign_attempt
.type sign_attempt, @function
sign_attempt:
    /* sign_w params: w_out, rho, rho_prime, y_staging, A_staging,
     * seca2b_scratch, gamma1_buf.  A_staging + gamma1_buf live in
     * dead sig during P1; c_poly (= NTT(c) post-P1) is now in overlay slack. */
    la   a0, W0_POLYVEC
    la   a1, sk                        /* rho is sk[0..32) */
    la   a2, sign_gamma1_buf
    la   a3, sign_y
    la   a4, sig                       /* A_staging at sig+1536 (after gamma1 buf) */
    addi a4, a4, 1536
    la   a5, sig                       /* seca2b scratch at sig+2560 */
    addi a5, a5, 1024
    addi a5, a5, 1536
    la   a6, sig                       /* gamma1 bitslice buf at sig+0 */
    jal  x1, sign_w

    /* sign_w0_w1_ctilde params: w_polyvec, mu, w1_repvec, sig,
     * w1_tmp_scratch, seca2b_scratch (sig+2560, same as in sign_w). */
    la   a0, W0_POLYVEC
    la   a1, mu
    la   a2, sign_w1_repvec
    la   a3, sig
    la   a4, sign_tmp
    la   a5, sig
    addi a5, a5, 1024
    addi a5, a5, 1536
    jal  x1, sign_w0_w1_ctilde

    la   a0, c_poly                    /* ntt_c output */
    la   a1, sign_tmp                /* aligned c~ stash */
    jal  x1, sign_c

    /* sign_z params: ntt_c, rho_prime(gamma1), sig_z_start,
     * z_staging, tmp_poly, cs1_share1, seca2b_scratch.  s1 is now derived
     * from rho_prime_shares in-loop, so a0 (was s1_packed) is unused. */
    la   a1, c_poly
    la   a2, sign_gamma1_buf
    la   a3, sig
    la   t0, mldsa_params
    lw   t0, MLDSA_PARAM_K_OFFSET(t0)
    slli t0, t0, 3                     /* CTILDEBYTES = K * 8 */
    add  a3, a3, t0
    la   a4, sign_c_poly_shares
    la   a5, sign_tmp
    la   a6, sign_y
    la   a7, sign_hint_b2a
    jal  x1, sign_z
    bne  a0, x0, sign_attempt

    /* sign_h params: sk_t0, ntt_c, packed_b, w1_repvec, sig_h.  s2 is now
     * derived from rho_prime_shares in-loop, so a1 (was s2_packed) is unused. */
    /* sign_h's sig_h start = sign_z's returned write cursor in a1
     * (= sig + CTILDEBYTES + L*POLYZ_PACKEDBYTES). */
    addi a5, a1, 0
    la   a0, sk
    addi a0, a0, 128
    la   a2, c_poly
    la   a3, W0_POLYVEC
    la   a4, sign_w1_repvec
    jal  x1, sign_h
    bne  a0, x0, sign_attempt
    li   a0, 0
    la   t0, mldsa_params
    lw   a1, MLDSA_PARAM_CRYPTO_BYTES_OFFSET(t0)
    ret

/* sign_w: matrix-vector multiplication w = A * y.  Column-wise loop over
 * j in [0, L): sample y[j] both shares via gamma1, NTT each share in place,
 * then for each i in [0, K): generate A[i][j] from rho and accumulate
 * A[i][j] * NTT(y[j])[d] into w[i][d].  Inverse-NTT w at the end.
 *
 * @param[out] a0: dptr_w, NSHARES * K * 1024 B accumulator (W0_POLYVEC).
 * @param[in]  a1: dptr_rho, 32 B (sk[0..32)).
 * @param[in]  a2: dptr_rho_prime, 128 B rho' seed (sign_gamma1_buf).
 * @param[in]  a3: dptr_y_staging, 2 KiB (y[j] both shares).
 * @param[in]  a4: dptr_A_staging, 1 KiB.
 * @param[in]  a5: dptr_seca2b_scratch, 1.5 KiB (forwarded to gamma1's b2a).
 * @param[in]  a6: dptr_gamma1_buf, 1.5 KiB bitslice-u staging.
 *
 * In/out: advances nonce counter in s11 by L (each gamma1 call uses it).
 * Clobbers a/t regs, s0-s10, w16/w22/w23.  Restores MOD = R|Q.
 */
.global sign_w
.type sign_w, @function
sign_w:
    /* Park pointer args in s-regs so internal jals can clobber a-regs. */
    addi s1, a0, 0           /* w_out */
    addi s0, a1, 0           /* rho */
    addi s9, a2, 0           /* rho_prime */
    addi s3, a3, 0           /* y_staging */
    addi s10, a4, 0          /* A_staging */
    addi s2, a5, 0           /* seca2b_scratch (was: rhoprime slot) */
    addi s7, a6, 0           /* gamma1_buf (was: gamma1_vec_const slot) */

    /* Zero each share's polyvec; t1 walks the contiguous buffer. */
    li t0, 31
    addi t1, s1, 0
    .rept NSHARES
    loopi W0_POLYS, 3
        loopi 32, 1
          bn.sid t0, 0(t1++)
        endloop
        nop
    endloop
    .endr

    /* Per-column constants. */
    li s6, W0_SHARE_STRIDE           /* stride between w shares */
    bn.xor w23, w23, w23             /* matrix nonce = byte(i) || byte(j) */
    li s5, 31                        /* w31 ref (unused but historical) */

    /* SHAKE128 cfg for poly_uniform (rho||i||j). */
    addi s4, x0, 34
    slli s4, s4, 5
    addi s4, s4, SHAKE128_CFG

    la   t0, mldsa_params
    lw   t0, MLDSA_PARAM_L_OFFSET(t0)
    loop t0, 94
        addi a0, s3, 0
        addi a1, s9, 0
        addi a2, s11, 0
        addi a3, s2, 0
        addi a4, s7, 0
        /* gamma_1 dispatches on a5 (2 => POLYZ_BITS 18 for ML-DSA-44, else 20);
         * gamma2 == 95232 selects ML-DSA-44. */
        la   t0, mldsa_params
        lw   t0, MLDSA_PARAM_GAMMA2_OFFSET(t0)
        li   t1, 95232
        li   a5, 2
        beq  t0, t1, _sign_w_gamma1_a_5
        li   a5, 3
_sign_w_gamma1_a_5:
        jal  x1, masked_poly_uniform_gamma_1
        addi s11, s11, 1

        /* Start the SHAKE128 operation for poly_uniform for A[0][j]. */
        csrrw x0, kmac_cfg, s4
        addi  a0, s0, 0
        bn.lid    x0, 0(a0)
        bn.wsrw   kmac_msg, w0
        addi      t0, x0, 2
        csrrw     x0, kmac_partial_write, t0
        bn.wsrw   kmac_msg, w23
        bn.wsrw 0x0, mod_x2 /* MOD = 2*R | 2*Q */
        /* Stage forward twiddles once per column; both shares reuse them. */
        jal  x1, gen_twiddles_fwd
        /* NTT each share of y[j] in place. */
        addi s8, s3, 0
        li   t5, NSHARES
        loop t5, 34
            la   x11, scratch
            addi a0, s8, 0
            addi a2, s8, 0
            jal  x1, ntt
            addi s8, s8, 1024
            /* Whitening */
            bn.xor w0, w0, w0
            bn.xor w1, w1, w1
            bn.xor w2, w2, w2
            bn.xor w3, w3, w3
            bn.xor w4, w4, w4
            bn.xor w5, w5, w5
            bn.xor w6, w6, w6
            bn.xor w7, w7, w7
            bn.xor w8, w8, w8
            bn.xor w9, w9, w9
            bn.xor w10, w10, w10
            bn.xor w11, w11, w11
            bn.xor w12, w12, w12
            bn.xor w13, w13, w13
            bn.xor w14, w14, w14
            bn.xor w15, w15, w15
            bn.xor w17, w17, w17
            bn.xor w18, w18, w18
            bn.xor w19, w19, w19
            bn.xor w20, w20, w20
            bn.xor w21, w21, w21
            bn.xor w24, w24, w24
            bn.xor w25, w25, w25
            bn.xor w26, w26, w26
            bn.xor w27, w27, w27
            bn.xor w28, w28, w28
            bn.xor w29, w29, w29
            bn.xor w30, w30, w30
        endloop
        la   t0, mldsa_params
        lw   t0, MLDSA_PARAM_K_OFFSET(t0)
        loop t0, 23
            /* Compute A[i][j]. */
            addi a1, s10, 0
            jal  x1, poly_uniform
            /* Increment the row index by 1. */
            bn.addi w23, w23, 256
            /* Start the SHAKE128 operation for poly_uniform for A[i+1][j]. */
            csrrw x0, kmac_cfg, s4
            addi  a0, s0, 0
            bn.lid    x0, 0(a0)
            bn.wsrw   kmac_msg, w0
            addi      t0, x0, 2
            csrrw     x0, kmac_partial_write, t0
            bn.wsrw   kmac_msg, w23
            /* For each share d:  w_d[i] += A[i][j] * y_d[j]. */
            addi s8, s3, 0
            addi s5, s1, 0
            li   t5, NSHARES
            loop t5, 8
                addi a0, s8, 0
                addi a1, s10, 0
                addi a2, s5, 0
                jal  x1, poly_pointwise_acc
                addi s8, s8, 1024
                add  s5, s5, s6
                /* Whitening */
                bn.xor w0, w0, w0
                bn.xor w1, w1, w1
            endloop
            addi s1, s1, 1024
        endloop
        /* Reset w pointer for next column. */
        la   s1, W0_POLYVEC
        /* Increment the column index in the nonce by one. */
        bn.addi w23, w23, 1
        /* Reset the row index in the nonce to zero. */
        bn.rshi w23, w23, bn0 >> 8
        bn.rshi w23, bn0, w23 >> 248
        bn.wsrw 0x0, w16 /* Restore MOD = R | Q */
    endloop

    bn.wsrw 0x0, mod_x2 /* MOD = 2*R | 2*Q */
    /* Stage inverse twiddles once; all NSHARES*K transforms reuse them. */
    jal x1, _inv_transform
    /* Inverse NTT each share's K polys; shares are W0_SHARE_STRIDE apart. */
    la  s1, W0_POLYVEC
    loopi NSHARES, 39
    addi a0, s1, 0
    la   t0, mldsa_params
    lw   t0, MLDSA_PARAM_K_OFFSET(t0)
    loop t0, 4
        la  x11, scratch
        jal x1, intt
        addi a0, a0, 1024
    endloop
    li  t0, W0_SHARE_STRIDE
    add s1, s1, t0
    /* Whitening */
    bn.xor w0, w0, w0
    bn.xor w1, w1, w1
    bn.xor w2, w2, w2
    bn.xor w3, w3, w3
    bn.xor w4, w4, w4
    bn.xor w5, w5, w5
    bn.xor w6, w6, w6
    bn.xor w7, w7, w7
    bn.xor w8, w8, w8
    bn.xor w9, w9, w9
    bn.xor w10, w10, w10
    bn.xor w11, w11, w11
    bn.xor w12, w12, w12
    bn.xor w13, w13, w13
    bn.xor w14, w14, w14
    bn.xor w15, w15, w15
    bn.xor w17, w17, w17
    bn.xor w18, w18, w18
    bn.xor w19, w19, w19
    bn.xor w20, w20, w20
    bn.xor w21, w21, w21
    bn.xor w24, w24, w24
    bn.xor w25, w25, w25
    bn.xor w26, w26, w26
    bn.xor w27, w27, w27
    bn.xor w28, w28, w28
    bn.xor w29, w29, w29
    bn.xor w30, w30, w30
    endloop

    bn.wsrw 0x0, w16 /* Restore MOD = R | Q */
    ret

/* sign_w0_w1_ctilde: per-poly decompose w[i] -> (w1[i], packed b'[i]);
 * polyw1_pack(w1[i]); SHAKE absorb; record w1 nonzero positions.
 * Finalize SHAKE -> c~ at sig[0..CTILDEBYTES).
 *
 * @param[inout] a0: dptr_w_polyvec.  Read as w (NSHARES*K*1024 B); the
 *                   K decompose iters overlay it in place with packed b'
 *                   (K*608 B per share at stride W0_SHARE_STRIDE).
 * @param[in]    a1: dptr_mu, 64 B (caller's mu).
 * @param[out]   a2: dptr_w1_repvec, K*32 B nonzero-summary of each w1[i].
 * @param[out]   a3: dptr_sig_ctilde, CTILDEBYTES at sig[0..).  Also
 *                   serves as decompose's scratch base (+16 for L3
 *                   alignment).
 * @param[scratch] a4: dptr_w1_tmp, 1 KiB temporary for decompose's w1
 *                   output and Keccak interim.
 * @param[scratch] a5: dptr_seca2b_scratch, 1.5 KiB (decompose internal).
 *
 * Clobbers: a/t regs, s0-s9.
 */
.global sign_w0_w1_ctilde
.type sign_w0_w1_ctilde, @function
sign_w0_w1_ctilde:
    /* Park pointer args.  s7 holds mu just long enough for the
     * keccak_send_message; the K-loop later overwrites it with NSHARES. */
    addi s0, a0, 0            /* w polyvec walker */
    addi s7, a1, 0            /* mu (consumed below) */
    addi s1, a2, 0            /* sign_w1_repvec walker */
    addi s3, a3, 0            /* sig (for c~ writes) */
    addi s2, a3, 0            /* decompose scratch base (sig, 32B aligned) */
    addi s4, a4, 0            /* w1 tmp scratch */
    addi s5, a5, 0            /* seca2b scratch */

    /* Initialize a SHAKE256 operation. */
    addi  a1, x0, CRHBYTES
    la    t0, mldsa_params
    lw    t2, MLDSA_PARAM_POLYW1_PACKEDBYTES_OFFSET(t0)
    lw    t0, MLDSA_PARAM_K_OFFSET(t0)
    loop  t0, 1
        add a1, a1, t2
    endloop
    slli  t0, a1, 5
    addi  t0, t0, SHAKE256_CFG
    csrrw x0, KECCAK_CFG_REG, t0

    /* Send mu (parked in s7). */
    li   a1, CRHBYTES
    addi a0, s7, 0
    jal  x1, keccak_send_message
    li   s6, W0_SHARE_STRIDE  /* stride between w_in / packed b' shares */

    /* Masked path: per poly, secdecompose produces an unmasked w1 (in
     * sign_tmp) and updates share 0 of w0 in place.  The K outer loop is
     * bne-based (not loopi) so it does not consume an ACC hardware loop-
     * stack slot -- secdecompose's call chain already uses every available
     * level. */
    li   s7, NSHARES
    la   t0, mldsa_params
    lw   s8, MLDSA_PARAM_K_OFFSET(t0)
    /* Packed b' poly i: share 0 at i*608, share 1 at W0_SHARE_STRIDE +
     * i*608.  Per-poly stride 608 < input stride 1024, so dumps stay
     * in the consumed slot of their own share. */
    addi s9, s0, 0
_decompose_loop:
    addi   a0, s4, 0
    addi   a1, s0, 0
    addi   a4, s6, 0
    /* secdecompose dispatches on a2 (2 = L2, else L35); set it + the matching
     * scratch off gamma2 (L2 = 95232). */
    la     t0, mldsa_params
    lw     t0, MLDSA_PARAM_GAMMA2_OFFSET(t0)
    li     t1, 95232
    bne    t0, t1, _decompose_l35
    la     a3, sign_w0_l2_seccompress_scratch
    la     a5, sign_w0_l2_b
    la     a6, sign_w0_l2_t_packed
    li     a2, 2
    jal x0, _decompose_call
_decompose_l35:
    addi   a3, s2, 0
    addi   a5, s9, 0
    add    a6, s9, s6
    addi   a7, s5, 0
    li     a2, 3
_decompose_call:
    jal    x1, secdecompose
    /* Pack w1, send to Keccak, record nonzero bits.  Runtime polyw1_pack
     * dispatches on a4 = K (selects the (Q-1)/88 vs (Q-1)/32 packing);
     * secdecompose clobbered a4, so reload it. */
    addi   a0, s2, 0
    addi   a1, s4, 0
    la     t0, mldsa_params
    lw     a4, MLDSA_PARAM_K_OFFSET(t0)
    jal    x1, polyw1_pack
    addi   a0, s2, 0
    la     t0, mldsa_params
    lw     a1, MLDSA_PARAM_POLYW1_PACKEDBYTES_OFFSET(t0)
    jal    x1, keccak_send_message
    addi   a0, s4, 0
    jal    x1, poly_nonzero_encode
    bn.sid x0, 0(s1++)
    addi   s0, s0, 1024
    addi   s9, s9, 608
    addi   s8, s8, -1
    bne    s8, x0, _decompose_loop

    /* Setup WDR */
    li t1, 8

    /* Read first 32 bytes of digest. */
    bn.wsrr w8, 0xA

    /* Get always-aligned temporary buffer. */
    la   t0, sign_tmp
    /* c~ layout depends on CTILDEBYTES (= K*8): 32 (K=4), 48 (K=6), 64 (K=8). */
    la   t3, mldsa_params
    lw   t3, MLDSA_PARAM_K_OFFSET(t3)
    li   t4, 4
    beq  t3, t4, _sign_pack_ctilde_44
    li   t4, 6
    beq  t3, t4, _sign_pack_ctilde_65
    /* ML-DSA-87 (K=8, CTILDEBYTES=64). */
    bn.sid  t1, 0(t0)
    bn.sid  t1, 0(s3)
    bn.wsrr w8, 0xA
    bn.sid  t1, 32(t0)
    bn.sid  t1, 32(s3)
    jal x0, _sign_pack_ctilde_done
_sign_pack_ctilde_44:
    /* ML-DSA-44 (K=4, CTILDEBYTES=32). */
    bn.sid  t1, 0(t0)
    bn.sid  t1, 0(s3)
    jal x0, _sign_pack_ctilde_done
_sign_pack_ctilde_65:
    /* ML-DSA-65 (K=6, CTILDEBYTES=48); signature unaligned, copy via GPRs. */
    bn.sid  t1, 0(t0)
    loopi 8, 4
        lw t2, 0(t0)
        sw t2, 0(s3)
        addi t0, t0, 4
        addi s3, s3, 4
    endloop
    bn.wsrr w8, 0xA
    bn.sid  t1, 0(t0)
    loopi 4, 4
        lw t2, 0(t0)
        sw t2, 0(s3)
        addi t0, t0, 4
        addi s3, s3, 4
    endloop
_sign_pack_ctilde_done:

    /* Finish the SHAKE-256 operation. */
    ret

/* sign_c: sample challenge c from c~ (poly_challenge); NTT(c) in place.
 *
 * @param[out] a0: dptr_ntt_c, 1024 B buffer for NTT(c).
 * @param[in]  a1: dptr_ctilde, 32-byte aligned source of c~.
 *
 * Clobbers: t-regs, a-regs, s0.  Restores MOD = R|Q.
 */
.global sign_c
.type sign_c, @function
sign_c:
    addi s0, a0, 0            /* park ntt_c_out across poly_challenge */
    /* Runtime poly_challenge takes a2 = CTILDEBYTES (= K*8), a3 = TAU; a0/a1
     * (output, c~) are already set by the caller. */
    la   t0, mldsa_params
    lw   t1, MLDSA_PARAM_K_OFFSET(t0)
    slli a2, t1, 3
    lw   a3, MLDSA_PARAM_TAU_OFFSET(t0)
    jal  x1, poly_challenge

    bn.wsrw 0x0, mod_x2
    jal  x1, gen_twiddles_fwd
    addi a0, s0, 0
    addi a2, a0, 0
    la   x11, scratch
    jal  x1, ntt
    bn.wsrw 0x0, w16
    ret

/* sign_z: z = y + c * s1.  Loops over L polys: unpack/b2a s1, NTT chain
 * c*s1, sample y (gamma1), z = y + c*s1, bound-check; on success, pack
 * z to sig[CTILDE..CTILDE+L*POLYZ_PACKEDBYTES) and zero the hint tail.
 *
 * @param[in]   a1: dptr_ntt_c, 1 KiB.
 * @param[in]   a2: dptr_rho_prime, 128 B.
 * @param[in]   a3: dptr_sig_z_start (sig + CTILDEBYTES).
 * @param[scratch] a4: dptr_z_staging, 3.3 KiB (sign_c_poly_shares-sized).
 * @param[scratch] a5: dptr_tmp_poly, 1 KiB (polyeta_unpack tgt + collapsed z).
 * @param[scratch] a6: dptr_cs1_share1, 1 KiB (also secb2amodq_eta/secboundcheck
 *                    bitslice buf).
 * @param[scratch] a7: dptr_seca2b_scratch, 3.3 KiB (forwarded to inner gadgets;
 *                    L5 also takes its +1536 as gamma1 staging).
 *
 * In/out: reads s11 (= nonce counter advanced by sign_w); uses
 * s11 - L as the per-iter gamma1 nonce base.
 * Returns a0 = 0 on success, a0 = 1 on rejection.
 */
/* Load one s1/s2 poly from the expanded sk: refresh the stored Boolean
 * bitsliced t-shares (t = eta - s) in place, B2A to arithmetic, coeff = eta - t.
 * Runtime ETA_KBITS = eta/2 + 2; POLYETA_PACKEDBYTES = ETA_KBITS * 32.
 *
 * @param[in]  a0: out (2 * 1024 B).
 * @param[in]  a1: src bitsliced shares (share 0 @ +0, share 1 @ +POLYETA).
 * @param[in]  a2: seca2b scratch.
 * @param[in]  a3: b2a Boolean buffer.
 */
_masked_eta_from_shares:
    addi sp, sp, -32
    sw   ra, 0(sp)
    sw   a0, 4(sp)
    sw   a1, 8(sp)
    sw   a2, 12(sp)
    sw   a3, 16(sp)

    la   t3, eta
    lw   t3, 0(t3)
    srli t3, t3, 1
    addi t3, t3, 2               /* t3 = ETA_KBITS (3 or 4) */
    slli t4, t3, 5              /* t4 = POLYETA_PACKEDBYTES (96 or 128) */

    /* Refresh both shares in place with fresh urnd (preserves the XOR). */
    addi t0, a1, 0
    add  t1, a1, t4
    li   t2, 0
    loop t3, 7
        bn.wsrr w2, urnd
        bn.lid  t2, 0(t0)
        bn.xor  w0, w0, w2
        bn.sid  t2, 0(t0++)
        bn.lid  t2, 0(t1)
        bn.xor  w0, w0, w2
        bn.sid  t2, 0(t1++)
    endloop

    /* B2A(t, ETA_KBITS): out receives arith shares of t. */
    lw   a0, 4(sp)
    lw   a1, 8(sp)
    add  a2, a1, t4
    addi a3, t3, 0
    lw   a4, 12(sp)
    lw   a5, 16(sp)
    jal  x1, secb2amodq_eta

    /* coeff = eta - t: share 0 = eta - t0, share 1 = -t1 (mod q). */
    la     t0, eta
    li     t1, 4
    bn.lid t1, 0(t0)
    lw   a0, 4(sp)
    li   t0, 0
    addi t1, a0, 0
    loopi 32, 3
        bn.lid t0, 0(t1)
        bn.subvm.8s w0, w4, w0
        bn.sid t0, 0(t1++)
    endloop
    bn.xor w0, w0, w0
    lw   a0, 4(sp)
    addi t1, a0, 1024
    loopi 32, 3
        bn.lid t0, 0(t1)
        bn.subvm.8s w0, w31, w0
        bn.sid t0, 0(t1++)
    endloop

    lw   ra, 0(sp)
    addi sp, sp, 32
    ret

.global sign_z
.type sign_z, @function
sign_z:
    /* Park pointer args. */
    li   s0, 0               /* ExpandS nonce: s1[j] uses nonce j */
    addi s7, a1, 0            /* NTT(c) */
    addi s4, a2, 0            /* rho_prime (gamma1 seed) */
    addi s9, a3, 0            /* sig_z write ptr (advances per polyz_pack) */
    addi s6, a4, 0            /* z staging */
    addi s2, a5, 0            /* sign_tmp */
    addi s3, a6, 0            /* c*s1 share 1 + bitslice buf */
    addi s10, a7, 0           /* seca2b scratch (eta/gamma1/boundcheck) */

    li   s5, NSHARES
    /* Per-iter gamma1 nonce starts at s11 - L (sign_w advanced s11 by L);
     * the loop runs until s8 climbs back to s11 (L iterations). */
    la   t0, mldsa_params
    lw   t0, MLDSA_PARAM_L_OFFSET(t0)
    sub  s8, s11, t0

    /* This loop computes z = (cp * s1) = y one element at a time, and does
       rejection sampling on each element before packing it into the signature. */
_sign_z_loop:
        /* Load s1[j] from the expanded sk (poly index j = nonce s0);
         * offset = j * 2*POLYETA (256 for K=6, else 192). */
        addi a0, s6, 0
        la   a1, s1s2_shares
        la   t2, mldsa_params
        lw   t0, MLDSA_PARAM_K_OFFSET(t2)
        li   t1, 6
        beq  t0, t1, _sz_k6
        slli t0, s0, 7
        slli t1, s0, 6
        add  t0, t0, t1
        beq  x0, x0, _sz_done
_sz_k6:
        slli t0, s0, 8
_sz_done:
        add  a1, a1, t0
        la   a2, sign_hint_b2a
        la   a3, sign_y
        jal  x1, _masked_eta_from_shares
        addi s0, s0, 1

        /* gadget's b2a clobbered w16/w22; rebuild from MOD (still R|Q). */
        bn.wsrr   w16, 0x0

        bn.shv.8S mod_x2, w16 << 1

        /* c*s1 share 0 at s2 (sign_tmp), share 1 at s3; delta in t3
         * (survives ntt/intt/poly_pointwise; t0-t2 don't). */
        bn.wsrw 0x0, mod_x2
        addi s1, s6, 0
        addi t6, s2, 0
        sub  t3, s3, s2
        loop s5, 45
            addi x10, s1, 0
            addi x12, t6, 0
            jal  x1, gen_twiddles_fwd
            la   x11, scratch
            jal  x1, ntt
            addi x10, t6, 0
            addi x11, s7, 0
            addi x12, t6, 0
            jal  x1, poly_pointwise
            jal  x1, _inv_transform
            addi x10, t6, 0
            la   x11, scratch
            jal  x1, intt
            addi s1, s1, 1024
            add  t6, t6, t3
            /* Whitening */
            bn.xor w0, w0, w0
            bn.xor w1, w1, w1
            bn.xor w2, w2, w2
            bn.xor w3, w3, w3
            bn.xor w4, w4, w4
            bn.xor w5, w5, w5
            bn.xor w6, w6, w6
            bn.xor w7, w7, w7
            bn.xor w8, w8, w8
            bn.xor w9, w9, w9
            bn.xor w10, w10, w10
            bn.xor w11, w11, w11
            bn.xor w12, w12, w12
            bn.xor w13, w13, w13
            bn.xor w14, w14, w14
            bn.xor w15, w15, w15
            bn.xor w17, w17, w17
            bn.xor w18, w18, w18
            bn.xor w19, w19, w19
            bn.xor w20, w20, w20
            bn.xor w21, w21, w21
            bn.xor w24, w24, w24
            bn.xor w25, w25, w25
            bn.xor w26, w26, w26
            bn.xor w27, w27, w27
            bn.xor w28, w28, w28
            bn.xor w29, w29, w29
            bn.xor w30, w30, w30
        endloop
        bn.wsrw 0x0, w16

        /* Sample y -> z_staging (overwrites bitsliced s1, now consumed). */
        addi a0, s6, 0
        addi a1, s4, 0
        addi a2, s8, 0
        addi a3, s10, 0           /* seca2b scratch */
        /* hint_b2a region is L5-sized (8192 B) for both params; gamma1
         * staging fits at scratch+1536. */
        addi a4, s10, 1536
        /* gamma_1 dispatches on a5 (2 => POLYZ_BITS 18 for ML-DSA-44, else 20);
         * gamma2 == 95232 selects ML-DSA-44. */
        la   t0, mldsa_params
        lw   t0, MLDSA_PARAM_GAMMA2_OFFSET(t0)
        li   t1, 95232
        li   a5, 2
        beq  t0, t1, _sign_z_gamma1_a_5
        li   a5, 3
_sign_z_gamma1_a_5:
        jal  x1, masked_poly_uniform_gamma_1
        addi s8, s8, 1

        /* z = y + c*s1 per share; same s2 / s3 split as NTT. */
        addi s1, s6, 0
        addi t6, s2, 0
        sub  t3, s3, s2
        loop s5, 8
            addi a0, s1, 0
            addi a1, t6, 0
            addi a2, s1, 0
            jal  x1, poly_add
            addi s1, s1, 1024
            add  t6, t6, t3
            /* Whitening */
            bn.xor w0, w0, w0
            bn.xor w1, w1, w1
        endloop

        /* Reduce z to unsigned canonical [0, q). */
        addi t0, s6, 0
        li   t1, 0
        loop s5, 5
            loopi 32, 3
                bn.lid t1, 0(t0)
                bn.addvm.8S w0, w0, w31
                bn.sid t1, 0(t0++)
            endloop
            bn.xor w0, w0, w0          /* Whitening */
        endloop


        /* secboundcheck on shared z, then AND-reduce the per-lane mask
         * to a 1-bit verdict; retry on fail.  Collapse z to sign_tmp
         * only after the bound check passes. */
        /* Load C_Z into w17 lane 0 (gadget broadcasts lane 0 internally). */
        li     t0, 17
        la     t1, c_z_const
        bn.lid t0, 0(t1)
        addi a0, s6, 0
        la   a2, lambda0_z_vec
        addi a3, s10, 0           /* seca2b scratch */
        addi a4, s3, 0            /* boundcheck bitslice buf */
        jal  x1, secboundcheck

        bn.not w0, w0
        bn.cmp w0, w31
        csrrs a2, FG0, x0
        andi a2, a2, 8
        xori a2, a2, 8
        /* Reject if ||z|| >= gamma1 - beta on any lane. */
        bne  a2, x0, _sign_z_reject

        addi a0, s2, 0
        addi a1, s6, 0
        jal  x1, secunmask_modq

        /* Reduce collapsed z to mod^{+-} for polyz_pack. */
        addi a0, s2, 0
        addi a1, s2, 0
        jal  x1, poly_reduce32

        /* Pack z[i] in place (aligned s2), then GPR-copy to the sig z-region
         * (unaligned for K=6). Runtime polyz_pack takes a4 = K. */
        addi a0, s2, 0
        addi a1, s2, 0
        la   t0, mldsa_params
        lw   a4, MLDSA_PARAM_K_OFFSET(t0)
        jal x1, polyz_pack
        sub  t0, a0, s2
        srli t0, t0, 2
        addi a1, s2, 0
        loop t0, 4
            lw   t1, 0(a1)
            sw   t1, 0(s9)
            addi a1, a1, 4
            addi s9, s9, 4
        endloop
        /* L iterations: loop until the gamma1 nonce s8 reaches s11. */
        bne  s8, s11, _sign_z_loop

    /* sig cursor is now *sig + CTILDEBYTES + L*POLYZ_PACKEDBYTES; return it
     * (a1) as sign_h's hint-write start, then zero the hint tail. */
    addi a1, s9, 0
    addi a0, s9, 0

    /* Set hint bytes at end of signature (length omega + k) to 0. Round to
       next word boundary. */
    la    t0, mldsa_params
    lw    t1, MLDSA_PARAM_OMEGA_OFFSET(t0)
    lw    t0, MLDSA_PARAM_K_OFFSET(t0)
    add   t1, t1, t0
    addi  t1, t1, 3
    srli  t1, t1, 2
    loop  t1, 2
      sw   x0, 0(a0)
      addi a0, a0, 4
    endloop

    li   a0, 0
    ret
_sign_z_reject:
    li   a0, 1
    ret

/* sign_h: per-poly hint computation.  Loops over K polys: unpack/b2a s2,
 * c*s2, build r-tilde from packed_b'[i], subtract c*s2, bound-check,
 * compute c*t0, combine, poly_make_hint, encode_h to sig tail.
 *
 * @param[in]  a0: dptr_sk_t0, K * POLYT0_PACKEDBYTES (packed t0).
 * @param[in]  a2: dptr_ntt_c, 1 KiB.
 * @param[in]  a3: dptr_packed_b (post-decompose b' share 0 base; share 1 at +W0_SHARE_STRIDE).
 * @param[in]  a4: dptr_w1_repvec, K * 32 B (nonzero summary written by sign_w0_w1_ctilde).
 * @param[out] a5: dptr_sig_h_start, write target for hint bytes (sig + CTILDE + L*POLYZ_PACKEDBYTES).
 *
 * Scratch (currently hardcoded via la): sign_c_poly_shares, sign_hint_b2a,
 * sign_y, sign_tmp.
 *
 * Returns a0 = 0 on success, a0 = 1 on rejection.
 */
.global sign_h
.type sign_h, @function
sign_h:
    /* Park pointer args; preserve s11 (nonce counter) for sign_z's retry. */
    addi s0, a0, 0            /* sk t0 walker */
    la   s2, mldsa_params     /* ExpandS nonce: s2[i] uses nonce L+i */
    lw   s2, MLDSA_PARAM_L_OFFSET(s2)
    addi s7, a2, 0            /* NTT(c) */
    addi s3, a3, 0            /* packed b' walker */
    addi s5, a4, 0            /* sign_w1_repvec walker */
    addi s9, a5, 0            /* sig hint write ptr */

    la   s10, sign_tmp

    /* Initialize the coefficient sum for the hint for post-check. */
    li  s4, 0

    /* Initialize the counter for the index in the hint vector. */
    li  s6, 0

    /* Hint loop counter. */
    la  s8, mldsa_params
    lw  s8, MLDSA_PARAM_K_OFFSET(s8)

    /* Normalize w0 to the [0, q) range (in-place).  The masked path
     * doesn't carry arithmetic w0; its r-tilde computation produces
     * canonical [0, q) directly via bn.subvm.8S. */

_mldsa_sign_hint_loop:

        /* Load s2[i] from the expanded sk (poly index L+i = nonce s2);
         * offset = (L+i) * 2*POLYETA (256 for K=6, else 192). */
        la   a0, sign_c_poly_shares
        la   a1, s1s2_shares
        la   t2, mldsa_params
        lw   t0, MLDSA_PARAM_K_OFFSET(t2)
        li   t1, 6
        beq  t0, t1, _sh_k6
        slli t0, s2, 7
        slli t1, s2, 6
        add  t0, t0, t1
        beq  x0, x0, _sh_done
_sh_k6:
        slli t0, s2, 8
_sh_done:
        add  a1, a1, t0
        la   a2, sign_hint_b2a
        la   a3, sign_hint_b2a
        addi a3, a3, 1536
        jal  x1, _masked_eta_from_shares
        addi s2, s2, 1

        /* b2a chain clobbered w16/w22; rebuild from MOD (still R|Q). */
        bn.wsrr   w16, 0x0

        bn.shv.8S mod_x2, w16 << 1

        /* Per-share NTT chain in place on sign_c_poly_shares -> c*s2. */
        la   s1, sign_c_poly_shares
        li   t0, NSHARES
        bn.wsrw 0x0, mod_x2 /* MOD = 2*R | 2*Q */
        loop t0, 45
            addi x10, s1, 0
            addi x12, s1, 0
            jal  x1, gen_twiddles_fwd
            la   x11, scratch
            jal  x1, ntt
            addi x10, s1, 0
            addi x11, s7, 0
            addi x12, s1, 0
            jal  x1, poly_pointwise
            jal  x1, _inv_transform
            addi x10, s1, 0
            la   x11, scratch
            jal  x1, intt
            addi s1, s1, 1024
            nop
            /* Whitening */
            bn.xor w0, w0, w0
            bn.xor w1, w1, w1
            bn.xor w2, w2, w2
            bn.xor w3, w3, w3
            bn.xor w4, w4, w4
            bn.xor w5, w5, w5
            bn.xor w6, w6, w6
            bn.xor w7, w7, w7
            bn.xor w8, w8, w8
            bn.xor w9, w9, w9
            bn.xor w10, w10, w10
            bn.xor w11, w11, w11
            bn.xor w12, w12, w12
            bn.xor w13, w13, w13
            bn.xor w14, w14, w14
            bn.xor w15, w15, w15
            bn.xor w17, w17, w17
            bn.xor w18, w18, w18
            bn.xor w19, w19, w19
            bn.xor w20, w20, w20
            bn.xor w21, w21, w21
            bn.xor w24, w24, w24
            bn.xor w25, w25, w25
            bn.xor w26, w26, w26
            bn.xor w27, w27, w27
            bn.xor w28, w28, w28
            bn.xor w29, w29, w29
            bn.xor w30, w30, w30
        endloop
        bn.wsrw 0x0, w16 /* Restore MOD = R | Q */

        /* Reduce c*s2 shares to unsigned canonical [0, q). */
        la   t0, sign_c_poly_shares
        li   t1, 0
        li   t2, NSHARES
        loop t2, 5
            loopi 32, 3
                bn.lid t1, 0(t0)
                bn.addvm.8S w0, w0, w31
                bn.sid t1, 0(t0++)
            endloop
            bn.xor w0, w0, w0          /* Whitening */
        endloop

        /* r-tilde reconstruction differs by gamma2 (matching secdecompose's
         * two regimes).  L2 (gamma2=95232): r-tilde_s = w0_s - c*s2_s
         * sharewise.  L3/5: r-tilde = (gamma2 - U) - c*s2 via b2a. */
        la   t0, mldsa_params
        lw   t0, MLDSA_PARAM_GAMMA2_OFFSET(t0)
        li   t1, 95232
        bne  t0, t1, _sign_h_rtilde_l35
        /* L2: r-tilde_s = w0_s - c*s2_s (mod q) sharewise.  Arithmetic w0[i]
         * lives in W0_POLYVEC (s3, shares W0_SHARE_STRIDE apart); c*s2 and the
         * r-tilde dst are in sign_c_poly_shares (shares 1024 apart). */
        la   t4, sign_c_poly_shares
        addi t5, s3, 0
        li   t2, 0
        li   t3, 2
        loopi 32, 4
            bn.lid t2, 0(t5++)
            bn.lid t3, 0(t4)
            bn.subvm.8S w0, w0, w2
            bn.sid t2, 0(t4++)
        endloop
        /* Whitening */
        bn.xor w0, w0, w0
        bn.xor w2, w2, w2
        li   t6, W0_SHARE_STRIDE
        add  t5, s3, t6
        loopi 32, 4
            bn.lid t2, 0(t5++)
            bn.lid t3, 0(t4)
            bn.subvm.8S w0, w0, w2
            bn.sid t2, 0(t4++)
        endloop
        jal x0, _sign_h_rtilde_done
_sign_h_rtilde_l35:
        /* r-tilde = (gamma2 - U) - c*s2; b2a in/out at sign_hint_b2a. */
        li   t2, 0
        li   t3, 31
        la   t0, sign_hint_b2a
        addi t1, s3, 0
        loopi 19, 2
            bn.lid t2, 0(t1++)
            bn.sid t2, 0(t0++)
        endloop
        loopi 5, 1
            bn.sid t3, 0(t0++)
        endloop
        bn.xor w0, w0, w0              /* Whitening */
        li   t1, W0_SHARE_STRIDE
        add  t1, s3, t1
        loopi 19, 2
            bn.lid t2, 0(t1++)
            bn.sid t2, 0(t0++)
        endloop
        loopi 5, 1
            bn.sid t3, 0(t0++)
        endloop

        /* gamma2-U b2a: scratch at sign_y (dead). */
        la   a1, sign_hint_b2a
        addi a0, a1, 1536
        la   a3, sign_y
        jal  x1, secb2amodq

        la   a0, sign_tmp
        la   a1, sign_hint_b2a
        addi a1, a1, 1536
        jal  x1, unbitslice

        la     t0, gamma2_vec_const
        li     t1, 1
        bn.lid t1, 0(t0)
        la     t4, sign_c_poly_shares
        la     t5, sign_tmp
        li     t2, 0
        li     t3, 2
        loopi 32, 5
            bn.lid t2, 0(t4)
            bn.lid t3, 0(t5++)
            bn.addvm.8S w0, w0, w2
            bn.subvm.8S w0, w1, w0
            bn.sid t2, 0(t4++)
        endloop

        /* Whitening */
        bn.xor w0, w0, w0
        bn.xor w1, w1, w1
        bn.xor w2, w2, w2
        bn.xor w3, w3, w3
        bn.xor w4, w4, w4
        bn.xor w5, w5, w5
        bn.xor w6, w6, w6
        bn.xor w7, w7, w7
        bn.xor w8, w8, w8
        bn.xor w9, w9, w9
        bn.xor w10, w10, w10
        bn.xor w11, w11, w11
        bn.xor w12, w12, w12
        bn.xor w13, w13, w13
        bn.xor w14, w14, w14
        bn.xor w15, w15, w15
        bn.xor w16, w16, w16
        bn.xor w17, w17, w17
        bn.xor w18, w18, w18
        bn.xor w19, w19, w19
        la   a0, sign_tmp
        la   a1, sign_hint_b2a
        addi a1, a1, 1536
        addi a1, a1, 768
        jal  x1, unbitslice

        la     t4, sign_c_poly_shares
        addi   t4, t4, 1024
        la     t5, sign_tmp
        li     t2, 0
        li     t3, 2
        loopi 32, 5
            bn.lid t2, 0(t4)
            bn.lid t3, 0(t5++)
            bn.addvm.8S w0, w0, w2
            bn.subvm.8S w0, w31, w0
            bn.sid t2, 0(t4++)
        endloop
_sign_h_rtilde_done:

        /* b2a chain clobbered w16/w22; rebuild from MOD (still R|Q). */
        bn.wsrr   w16, 0x0
        bn.shv.8S mod_x2, w16 << 1

        /* secboundcheck on shared r-tilde, AND-reduce verdict into s8. */
        /* Load C_R into w17 lane 0 (gadget broadcasts lane 0 internally). */
        li     t0, 17
        la     t1, c_r_const
        bn.lid t0, 0(t1)
        la   a0, sign_c_poly_shares
        la   a2, lambda0_r_vec
        la   a3, sign_hint_b2a
        la   a4, sign_y
        jal  x1, secboundcheck

        bn.not w0, w0
        bn.cmp w0, w31
        csrrs a2, FG0, x0
        andi a2, a2, 8
        xori a2, a2, 8
        /* Reject if ||rtilde|| >= gamma2 - beta on any lane. */
        bne  a2, x0, _sign_h_reject

        la   a0, sign_hint_b2a
        la   a1, sign_c_poly_shares
        jal  x1, secunmask_modq

        /* Restore w16 = MOD (secunmask_modq's contract leaves low32 = q). */
        bn.wsrr w16, 0x0

        /* Unpack the next polynomial from t0. */
        addi a0, s10, 0
        addi a1, s0, 0
        jal  x1, polyt0_unpack

        /* Update the packed t0 pointer. */
        addi s0, a1, 0

        bn.wsrw 0x0, mod_x2 /* MOD = 2*R | 2*Q */

        /* Compute ntt(t0[i]) in-place. */
        jal x1, gen_twiddles_fwd
        addi a0, s10, 0
        addi a2, a0, 0
        la  x11, scratch
        jal x1, ntt

        /* tmp = cp * t0 */
        addi a0, s10, 0
        addi a1, s7, 0
        addi a2, s10, 0
        jal  x1, poly_pointwise

        /* Inverse NTT on tmp (reuse fwd table still in scratch). */
        jal x1, _inv_transform
        addi a0, s10, 0
        la  x11, scratch
        jal x1, intt

        bn.wsrw 0x0, w16 /* Restore MOD = R | Q */

        /* w0[i] += tmp */
        la   a0, sign_hint_b2a
        addi a1, s10, 0
        addi a2, a0, 0
        jal  x1, poly_add

        /* h = reduce32(tmp) to move to mod^{+-} for bound check */
        addi a0, s10, 0
        addi a1, s10, 0
        jal  x1, poly_reduce32

        /* chknorm(h, gamma2) */
        la   a1, mldsa_params
        lw   a1, MLDSA_PARAM_GAMMA2_OFFSET(a1)
        addi a0, s10, 0
        jal  x1, poly_chknorm

        /* Reject if ||c*t0|| >= gamma2 on any lane. */
        bne a2, x0, _sign_h_reject

        /* h[i] = make_hint(w0[i], w1[i]); runtime poly_make_hint takes
         * a2 = GAMMA2. */
        addi   a0, s10, 0
        la     a1, sign_hint_b2a
        la     a2, mldsa_params
        lw     a2, MLDSA_PARAM_GAMMA2_OFFSET(a2)
        bn.lid x0, 0(s5++)
        jal    x1, poly_make_hint

        /* Update the coefficient sum accumulator (saving previous value). */
        add  a2, s4, 0
        add  s4, s4, a0

        /* If the accumulator (# nonzero coeffs in h) is > omega, reject. */
        la   t0, mldsa_params
        lw   t0, MLDSA_PARAM_OMEGA_OFFSET(t0)
        sub  t0, t0, s4
        srli t0, t0, 31

        /* Reject if hint weight > omega. */
        bne t0, x0, _sign_h_reject

        /* Encode h[i] into the signature; runtime poly_encode_h takes
         * a4 = OMEGA. */
        addi a0, s9, 0
        addi a1, s10, 0
        addi a3, s6, 0
        la   a4, mldsa_params
        lw   a4, MLDSA_PARAM_OMEGA_OFFSET(a4)
        jal  x1, poly_encode_h

        /* Increment i. */
        addi s6, s6, 1
        /* Advance to next poly: L2 carries arithmetic w0 (1024 stride), L3/5
         * the packed b' (608 stride). */
        la   t0, mldsa_params
        lw   t0, MLDSA_PARAM_GAMMA2_OFFSET(t0)
        li   t1, 95232
        bne  t0, t1, _sign_h_stride_l35
        addi s3, s3, 1024
        jal x0, _sign_h_stride_done
_sign_h_stride_l35:
        addi s3, s3, 608
_sign_h_stride_done:
        /* Decrement remaining-iter count and loop while > 0. */
        addi s8, s8, -1
        bne  s8, x0, _mldsa_sign_hint_loop

    li   a0, 0
    ret
_sign_h_reject:
    li   a0, 1
    ret
#else
    /* Store pointer parameters. */
    la  t0, dptr_sig
    sw  a0, 0(t0)

    /* External mu: dmem[mu] is supplied by the caller. */

    /* Initialize a SHAKE256 operation. */
    addi  a1, x0, SEEDBYTES
    addi  a1, a1, RNDBYTES
    addi  a1, a1, CRHBYTES
    slli  t0, a1, 5
    addi  t0, t0, SHAKE256_CFG
    csrrw x0, KECCAK_CFG_REG, t0

    /* Send K component of sk (sk[32:64]) to the Keccak core. */
    li   a1, SEEDBYTES /* set message length to SEEDBYTES */
    la   a0, sk
    addi a0, a0, 32
    jal x1, keccak_send_message

    /* Send rnd to the Keccak core. */
    li  a1, RNDBYTES /* set message length to RNDBYTES */
    la  a0, rnd
    jal x1, keccak_send_message

    /* Send mu to the Keccak core. */
    li  a1, CRHBYTES /* set message length to CRHBYTES */
    la  a0, mu
    jal x1, keccak_send_message

    /* Setup WDR */
    li t1, 8

    la      a0, rhoprime
    bn.wsrr w8, 0xA     /* KECCAK_DIGEST */
    bn.sid  t1, 0(a0++) /* Store into rhoprime buffer */
    bn.wsrr w8, 0xA     /* KECCAK_DIGEST */
    bn.sid  t1, 0(a0++) /* Store into rhoprime buffer */

    /* Finish the SHAKE-256 operation. */

    /* Prepare modulus */
    #define mod_x2 w22
    bn.wsrr   w16, 0x0 /* w16 = MOD = R | Q */
    bn.shv.8S mod_x2, w16 << 1 /* mod_x2 = 2*R | 2*Q */

    li s11, 0 /* nonce */

_rej_crypto_sign_signature_internal:
    /* Matrix-vector multiplication */

    /* Get destination pointer. */
    la s1, w0_polyvec

    /* Initialize destination to 0. */
    li t0, 31
    addi t1, s1, 0
    la t2, mldsa_params
    lw t3, MLDSA_PARAM_K_OFFSET(t2)
    LOOP t3, 3
        LOOPI 32, 1
          bn.sid t0, 0(t1++)
        nop

    /* Load the constant for resetting the w pointer (K * 1024). */
    slli s6, t3, 10

    /* Initialize the nonce for matrix expansion. This value should be
         byte(i) || byte(j)
       for entry A[i][j]. */
    bn.xor w23, w23, w23

    /* Load a constant pointer to the zero wide register. */
    li s5, 31


    /* Load other pointers. */
    la   s8, y_poly
    la   s10, tmp_poly
    la   s0, sk /* rho is the first 32B of sk */
    la   s2, rhoprime

    /* Precompute the SHAKE128 configuration for poly_uniform. */
    addi  s4, x0, 34
    slli  s4, s4, 5
    addi  s4, s4, SHAKE128_CFG

    /* Compute A * y, computing the values for A and y on the fly.

       We compute column-wise so that we genearate elements of y only once; in
       pseudocode, this computation does:

         for j in 0..l-1:
           yj = ntt(y[j])
           for i in 0..k-1:
             w[i] += A[i][j] * yj
    */
    la t2, mldsa_params
    lw t3, MLDSA_PARAM_L_OFFSET(t2)
    LOOP t3, 46
        /* Zero the buffer for y[j]. */
        addi  t0, s8, 0
        loopi 32, 1
          bn.sid s5, 0(t0++)
        /* Compute y[j]. */
        addi a0, s8, 0
        addi a1, s2, 0
        addi a2, s11, 0 /* y sampling nonce */
        la t2, mldsa_params
        lw a4, MLDSA_PARAM_K_OFFSET(t2)
        jal  x1, poly_uniform_gamma_1
        addi s11, a2, 1 /* a2 should be preserved after execution */
        /* Start the SHAKE128 operation for poly_uniform for A[0][j]. */
        csrrw x0, kmac_cfg, s4
        addi  a0, s0, 0
        bn.lid    x0, 0(a0)
        bn.wsrw   kmac_msg, w0
        addi      t0, x0, 2
        csrrw     x0, kmac_partial_write, t0
        bn.wsrw   kmac_msg, w23
        bn.wsrw 0x0, mod_x2 /* MOD = 2*R | 2*Q */
        /* Compute ntt(y[j]). */
        addi a0, s8, 0
        addi a2, s8, 0
        jal x1, ntt
        la t2, mldsa_params
        lw t3, MLDSA_PARAM_K_OFFSET(t2)
        LOOP t3, 15
            /* Compute A[i][j]. */
            addi a1, s10, 0
            jal  x1, poly_uniform
            /* Increment the row index by 1. */
            bn.addi w23, w23, 256
            /* Start the SHAKE128 operation for poly_uniform for A[i+1][j]. */
            csrrw x0, kmac_cfg, s4
            addi  a0, s0, 0
            bn.lid    x0, 0(a0)
            bn.wsrw   kmac_msg, w0
            addi      t0, x0, 2
            csrrw     x0, kmac_partial_write, t0
            bn.wsrw   kmac_msg, w23
            addi a0, s8, 0
            addi a1, s10, 0
            addi a2, s1, 0 /* *w[i] */
            /* Add A[i][j] * y[j] to w[i]. */
            jal  x1, poly_pointwise_acc
            /* Increment the w pointer. */
            addi s1, s1, 1024
        /* Reset w pointer. */
        sub  s1, s1, s6
        /* Increment the column index in the nonce by one. */
        bn.addi w23, w23, 1
        /* Reset the row index in the nonce to zero. */
        bn.rshi w23, w23, bn0 >> 8
        bn.rshi w23, bn0, w23 >> 248
        bn.wsrw 0x0, w16 /* Restore MOD = R | Q */

    bn.wsrw 0x0, mod_x2 /* MOD = 2*R | 2*Q */
    /* Inverse NTT on w */
    la  a0, w0_polyvec

    la t2, mldsa_params
    lw t3, MLDSA_PARAM_K_OFFSET(t2)
    LOOP t3, 2
        jal x1, intt
        /* Go to next input polynomial */
        addi a0, a0, 1024

    bn.wsrw 0x0, w16 /* Restore MOD = R | Q */

    /* Random oracle */
    /* Initialize a SHAKE256 operation. */
    addi  a1, x0, CRHBYTES
    la t2, mldsa_params
    lw t4, MLDSA_PARAM_POLYW1_PACKEDBYTES_OFFSET(t2)
    LOOP t3, 1
        add a1, a1, t4
    slli  t0, a1, 5
    addi  t0, t0, SHAKE256_CFG
    csrrw x0, KECCAK_CFG_REG, t0

    /* Send mu to the Keccak core. */
    li  a1, CRHBYTES /* set mu length to CRHBYTES */
    la  a0, mu
    jal x1, keccak_send_message

    /* Save some pointers for loop. */
    la  s0, w0_polyvec
    la  s1, w1_repvec
    la  s4, tmp_poly

    /* Save the signature pointer (ctilde destination). */
    la  s3, dptr_sig
    lw  s3, 0(s3)
    /* Pack w1 into c_poly: 32-byte aligned and free until poly_challenge. */
    la  s2, c_poly
    la   t0, mldsa_params
    lw   t3, MLDSA_PARAM_K_OFFSET(t0)

    /* This loop:
         - decomposes each polynomial w[i] into w0[i] and w1[i]
         - packs w1[i] and sends it to the Keccak core
         - records the nonzero high bits of w1[i] for later use

       Afterwards, the w1[i] value can be discarded, so we do not need to keep
       two w-sized polyvecs in scope at once. */
    LOOP t3, 19
        /* Decompose w and store w0 in-place, w1 in tmp. */
        addi   a0, s0, 0
        addi   a1, s4, 0
        addi   a2, s0, 0
        la t2, mldsa_params
        lw a4, MLDSA_PARAM_K_OFFSET(t2)
        jal    x1, poly_decompose
        /* Pack w1. */
        addi   a0, s2, 0
        addi   a1, s4, 0
        jal    x1, polyw1_pack
        /* Send packed w1 to the Keccak core. */
        addi   a0, s2, 0
        la t2, mldsa_params
        lw a1, MLDSA_PARAM_POLYW1_PACKEDBYTES_OFFSET(t2)
        jal    x1, keccak_send_message
        /* Calculate the coefficients of w1 that are nonzero mod q, and store them. */
        addi   a0, s4, 0
        jal    x1, poly_nonzero_encode
        bn.sid x0, 0(s1++)
        /* Increment w pointer. */
        addi s0, s0, 1024

    /* Setup WDR */
    li t1, 8

    /* Read first 32 bytes of digest. */
    bn.wsrr w8, 0xA

    /* Get always-aligned temporary buffer. */
    la   t0, tmp_poly

    /* Pack ctilde into temp buffer and signature; layout depends on K. */
    la   t3, mldsa_params
    lw   t3, MLDSA_PARAM_K_OFFSET(t3)
    li   t4, 4
    beq  t3, t4, _sign_pack_ctilde_44
    li   t4, 6
    beq  t3, t4, _sign_pack_ctilde_65
    /* ML-DSA-87 (K=8, CTILDEBYTES=64). */
    bn.sid  t1, 0(t0)
    bn.sid  t1, 0(s3)
    bn.wsrr w8, 0xA
    bn.sid  t1, 32(t0)
    bn.sid  t1, 32(s3)
    jal x0, _sign_pack_ctilde_done
_sign_pack_ctilde_44:
    /* ML-DSA-44 (K=4, CTILDEBYTES=32). */
    bn.sid  t1, 0(t0)
    bn.sid  t1, 0(s3)
    jal x0, _sign_pack_ctilde_done
_sign_pack_ctilde_65:
    /* ML-DSA-65 (K=6, CTILDEBYTES=48). The signature is not aligned, so
       copy via GPRs. */
    bn.sid  t1, 0(t0)
    LOOPI 8, 4
        lw t2, 0(t0)
        sw t2, 0(s3)
        addi t0, t0, 4
        addi s3, s3, 4
    bn.wsrr w8, 0xA
    bn.sid  t1, 0(t0)
    LOOPI 4, 4
        lw t2, 0(t0)
        sw t2, 0(s3)
        addi t0, t0, 4
        addi s3, s3, 4
_sign_pack_ctilde_done:

    /* Finish the SHAKE-256 operation. */

    /* Challenge */
    /* CTILDE was temporarily stored in tmp_poly. Re-use here because it is aligned,
       for CTILDEBYTES = 48 as well */
    la   a0, c_poly
    la   a1, tmp_poly
    la   t0, mldsa_params
    lw   t1, MLDSA_PARAM_K_OFFSET(t0)
    slli a2, t1, 3  /* CTILDEBYTES = K * 8 */
    lw   a3, MLDSA_PARAM_TAU_OFFSET(t0)
    jal  x1, poly_challenge

    bn.wsrw 0x0, mod_x2 /* MOD = 2*R | 2*Q */

    /* NTT(cp) */
    la   a0, c_poly /* Input */
    addi a2, a0, 0  /* Output inplace */
    jal  x1, ntt

    bn.wsrw 0x0, w16 /* Restore MOD = R | Q */

    /* Load pointer to packed s1 */
    la   s0, sk
    addi s0, s0, 128

    /* Reset the nonce for y and set up a constant for poly_uniform_gamma1. */
    la   t0, mldsa_params
    lw   t1, MLDSA_PARAM_L_OFFSET(t0)
    sub  s8, s11, t1

    /* Save some pointers. */
    la   s2, tmp_poly
    la   s3, rhoprime
    la   s7, c_poly
    la   s9, dptr_sig
    lw   s9, 0(s9)
    lw   t1, MLDSA_PARAM_K_OFFSET(t0)
    slli t1, t1, 3      /* CTILDEBYTES = K * 8 */
    add  s9, s9, t1     /* c is already packed */

    /* This loop computes z = (cp * s1) = y one element at a time, and does
       rejection sampling on each element before packing it into the signature.
       Uses a regular branch-back loop so we can bail out early on rejection. */
    li s4, 0
_rejsmpl_loop:
        /* Unpack the next polynomial from s1. */
        addi a0, s2, 0
        addi a1, s0, 0
        la t2, mldsa_params
        lw a4, MLDSA_PARAM_K_OFFSET(t2)
        jal x1, polyeta_unpack
        /* Update the packed s1 pointer. */
        addi s0, a1, 0

        bn.wsrw 0x0, mod_x2 /* MOD = 2*R | 2*Q */

        /* Compute ntt(s1). */
        addi a0, s2, 0
        addi a2, s2, 0
        jal x1, ntt
        /* z = cp * s1 */
        addi a0, s2, 0
        addi a1, s7, 0
        addi a2, s2, 0
        jal  x1, poly_pointwise
        /* After poly_pointwise, w16 is still R | Q and MOD is still 2*R | 2*Q */

        /* Inverse NTT on z */
        addi a0, s2, 0
        jal x1, intt

        bn.wsrw 0x0, w16 /* Restore MOD = R | Q */

        /* Sample the next value of y and add it to z. */
        addi a0, s2, 0
        addi a1, s3, 0
        addi a2, s8, 0
        la t2, mldsa_params
        lw a4, MLDSA_PARAM_K_OFFSET(t2)
        jal  x1, poly_uniform_gamma_1

        /* Update the nonce for y. */
        addi s8, a2, 1

        /* reduce32(z) to move to mod^{+-} for bound check */
        addi a0, s2, 0
        addi a1, s2, 0
        jal x1, poly_reduce32

        /* chknorm */
        addi a0, s2, 0
        la   t2, mldsa_params
        lw   a1, MLDSA_PARAM_GAMMA1_MINUS_BETA_OFFSET(t2)
        jal x1, poly_chknorm

        bne a2, x0, _rej_crypto_sign_signature_internal

        /* Pack z[i] in place, then GPR-copy into the unaligned sig slot. */
        addi a0, s2, 0
        addi a1, s2, 0
        la t2, mldsa_params
        lw a4, MLDSA_PARAM_K_OFFSET(t2)
        jal x1, polyz_pack
        sub  t0, a0, s2   /* POLYZ_PACKEDBYTES */
        srli t0, t0, 2
        addi a1, s2, 0
        LOOP t0, 4
            lw   t1, 0(a1)
            sw   t1, 0(s9)
            addi a1, a1, 4
            addi s9, s9, 4
    addi s4, s4, 1
    la t0, mldsa_params
    lw t1, MLDSA_PARAM_L_OFFSET(t0)
    bne s4, t1, _rejsmpl_loop

    /* get *sig + CTILDEBYTES + L*POLYZ_PACKEDBYTES */
    addi a0, s9, 0

    /* Set hint bytes at end of signature (length omega + k) to 0. Round to
       next word boundary. */
    lw    t1, MLDSA_PARAM_OMEGA_OFFSET(t0)
    lw    t2, MLDSA_PARAM_K_OFFSET(t0)
    add   t1, t1, t2
    addi  t1, t1, 3
    srli  t1, t1, 2
    LOOP  t1, 2
      sw   x0, 0(a0)
      addi a0, a0, 4

    addi a0, s9, 0

    /* Load pointers to packed S2 and T0 within sk. */
    la   s0, sk
    lw   t1, MLDSA_PARAM_SK_S2_OFFSET_OFFSET(t0)
    add  s2, s0, t1
    lw   t1, MLDSA_PARAM_SK_T0_OFFSET_OFFSET(t0)
    add  s0, s0, t1

    /* Initialize some pointers for the loop. */
    la  s3, w0_polyvec
    la  s5, w1_repvec
    la  s7, c_poly
    la  s10, tmp_poly

    /* Initialize the coefficient sum for the hint for post-check. */
    li  s4, 0

    /* Initialize the counter for the index in the hint vector. */
    li  s6, 0

    /* Initialize the register that says whether the checks failed. */
    li  s8, 0

    /* Normalize w0 to the [0, q) range (in-place). */
    addi   a0, s3, 0
    li     t1, 1
    la     t0, modulus
    bn.lid t1, 0(t0)
    la t0, mldsa_params
    lw t1, MLDSA_PARAM_K_OFFSET(t0)
    LOOP t1, 6
        LOOPI 32, 4
            bn.lid      x0, 0(a0)
            bn.addv.8S  w0, w0, w1
            bn.addvm.8S w0, bn0, w0
            bn.sid      x0, 0(a0++)
        NOP

    /* This loop computes the hint one element at a time, and performs
       rejection sampling. For each index i=0..k-1, it does:

         tmp = cp * s2[i]
         w0[i] -= tmp
         tmp = reduce32(w0[i])
         if not poly_chknorm(tmp, gamma - beta):
           reject
         tmp = cp * t0[i]
         h = reduce32(tmp)
         if not poly_chknorm(h, gamma):
           reject
         w0[i] += h
         if not poly_chknorm(w0[i], gamma - beta):
           reject
         make_hint(h, w0[i], w1[i]) # gets written directly into signature
     */
    la t0, mldsa_params
    lw t1, MLDSA_PARAM_K_OFFSET(t0)
    LOOP t1, 85
        /* If there was a failure, skip to the end of the
           loop body (because of architectural loop rules, we have to complete
           all iterations). */
        bne  s8, x0, _mldsa_sign_hint_loop_end

        /* Unpack the next polynomial from s2. */
        addi a0, s10, 0
        addi a1, s2, 0
        la t0, mldsa_params
        lw a4, MLDSA_PARAM_K_OFFSET(t0)
        jal  x1, polyeta_unpack
        addi a0, a0, -1024

        /* Update the packed s2 pointer. */
        addi s2, a1, 0

        bn.wsrw 0x0, mod_x2 /* MOD = 2*R | 2*Q */

        /* Compute ntt(s2[i]) in-place. */
        addi a2, a0, 0
        jal x1, ntt

        /* tmp = cp * s2 */
        addi a0, s10, 0
        addi a1, s7, 0
        addi a2, s10, 0
        jal  x1, poly_pointwise

        /* Inverse NTT on tmp */
        addi a0, s10, 0
        jal x1, intt

        bn.wsrw 0x0, w16 /* Restore MOD = R | Q */

        /* w0[i] -= tmp */
        addi a0, s3, 0
        addi a1, s10, 0
        addi a2, s3, 0
        jal  x1, poly_sub

        /* tmp = reduce32(w0[i]) to move to mod^{+-} for bound check */
        addi a0, s3, 0
        addi a1, s10, 0
        jal  x1, poly_reduce32

        /* chknorm(tmp, gamma2 - beta) */
        addi a0, s10, 0
        la   t0, mldsa_params
        lw   a1, MLDSA_PARAM_GAMMA2_MINUS_BETA_OFFSET(t0)
        jal  x1, poly_chknorm

        /* Update the continuation register. */
        or  s8, s8, a2

        /* Unpack the next polynomial from t0. */
        addi a0, s10, 0
        addi a1, s0, 0
        jal  x1, polyt0_unpack

        /* Update the packed t0 pointer. */
        addi s0, a1, 0

        bn.wsrw 0x0, mod_x2 /* MOD = 2*R | 2*Q */

        /* Compute ntt(t0[i]) in-place. */
        addi a0, s10, 0
        addi a2, a0, 0
        jal x1, ntt

        /* tmp = cp * t0 */
        addi a0, s10, 0
        addi a1, s7, 0
        addi a2, s10, 0
        jal  x1, poly_pointwise

        /* Inverse NTT on tmp */
        addi a0, s10, 0
        jal x1, intt

        bn.wsrw 0x0, w16 /* Restore MOD = R | Q */

        /* w0[i] += tmp */
        addi a0, s3, 0
        addi a1, s10, 0
        addi a2, s3, 0
        jal  x1, poly_add

        /* h = reduce32(tmp) to move to mod^{+-} for bound check */
        addi a0, s10, 0
        addi a1, s10, 0
        jal  x1, poly_reduce32

        /* chknorm(h, gamma2) */
        la   t0, mldsa_params
        lw   a1, MLDSA_PARAM_GAMMA2_OFFSET(t0)
        addi a0, s10, 0
        jal  x1, poly_chknorm

        /* Update the continuation register. */
        or  s8, s8, a2

        /* h[i] = make_hint(w0[i], w1[i]) */
        addi   a0, s10, 0
        addi   a1, s3, 0
        la     t0, mldsa_params
        lw     a2, MLDSA_PARAM_GAMMA2_OFFSET(t0)
        bn.lid x0, 0(s5++)
        jal    x1, poly_make_hint

        /* Update the coefficient sum accumulator (saving previous value). */
        add  a2, s4, 0
        add  s4, s4, a0

        /* If the accumulator (# nonzero coeffs in h) is > omega, reject. */
        la   t0, mldsa_params
        lw   t1, MLDSA_PARAM_OMEGA_OFFSET(t0)
        sub  t0, t1, s4
        srli t0, t0, 31

        /* Update the continuation register. */
        or  s8, s8, t0

        /* Skip encode in case of rejection. */
        bne  s8, x0, _mldsa_sign_hint_loop_end
        /* Encode h[i] into the signature. */
        addi a0, s9, 0
        addi a1, s10, 0
        addi a3, s6, 0
        la   t0, mldsa_params
        lw   a4, MLDSA_PARAM_OMEGA_OFFSET(t0)
        jal  x1, poly_encode_h

        /* Increment i. */
        addi s6, s6, 1
        _mldsa_sign_hint_loop_end:
        /* Update pointer into w0. */
        addi s3, s3, 1024

    /* Reject the signature if any conditions failed in the hint loop. */
    bne  s8, x0, _rej_crypto_sign_signature_internal

    /* Return success and signature length */
    li a0, 0
    la t0, mldsa_params
    lw a1, MLDSA_PARAM_CRYPTO_BYTES_OFFSET(t0)
  ret
#endif
