/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "inner.h"
#include <stdio.h>
#include <stdlib.h>
#include "../../inc/bearssl.h"

#define U      (2 + ((BR_MAX_RSA_FACTOR + 30) / 31))
#define TLEN   (8 * U)


/*
 * Fake RNG that returns exactly the provided bytes.
 */


/*
 * Make a random integer of the provided size. The size is encoded.
 * The header word is untouched.
 */

static void
mkrand(const br_prng_class **rng, uint32_t *x, uint32_t esize)
{
        size_t u, len;
        unsigned m;

        len = (esize + 31) >> 5;
        (*rng)->generate(rng, x + 1, len * sizeof(uint32_t));
        for (u = 1; u < len; u ++) {
                x[u] &= 0x7FFFFFFF;
        }
        m = esize & 31;
        if (m == 0) {
                x[len] &= 0x7FFFFFFF;
        } else {
                x[len] &= 0x7FFFFFFF >> (31 - m);
        }
}


/* see bearssl_rsa.h */
uint32_t
br_rsa_i31_private_safe(unsigned char *x, const br_rsa_private_key *sk)
{
	const unsigned char *p, *q;
	size_t plen, qlen;
	size_t fwlen;
	uint32_t p0i, q0i;
	size_t xlen, u;
	uint32_t tmp[1 + TLEN];
	long z;
	uint32_t *mp, *mq, *s1, *s2, *t1, *t2, *t3;
	uint32_t r;
	



	br_hmac_drbg_context rng;

        br_hmac_drbg_init(&rng, &br_sha256_vtable, "seed for RSA SAFE", 19);	
	/*
	 * Create small random numbers r1, r2, r3
	 */

        uint32_t r1[2], r2[2], r3[2];	
	
	mkrand(&rng.vtable, r1 + 1, 31);
	mkrand(&rng.vtable, r2 + 1, 31);
	mkrand(&rng.vtable, r3 + 1, 31);
	
	r1[0] = br_i31_bit_length(r1+1, 1);
	r2[0] = br_i31_bit_length(r2+1, 1);
	r3[0] = br_i31_bit_length(r3+1, 1);
			
	
	/*
	 * Compute the actual lengths of p and q, in bytes.
	 * These lengths are not considered secret (we cannot really hide
	 * them anyway in constant-time code).
	 */


	p = sk->p;
	plen = sk->plen;
	while (plen > 0 && *p == 0) {
		p ++;
		plen --;
	}
	q = sk->q;
	qlen = sk->qlen;
	while (qlen > 0 && *q == 0) {
		q ++;
		qlen --;
	}

	/*
	 * Compute the maximum factor length, in words.
	 */
	z = (long)(plen > qlen ? plen : qlen) << 3;
	fwlen = 1 + 1;  // we will multiply q and p by r1, r2 therefore + 1
	while (z > 0) {
		z -= 31;
		fwlen ++;
	}

	/*
	 * Round up the word length to an even number.
	 */
	fwlen += (fwlen & 1);

	/*
	 * We need to fit at least 6 values in the stack buffer.
	 */
	if (6 * fwlen > TLEN) {
		return 0;
	}

	/*
	 * Compute modulus length (in bytes).
	 */
	xlen = (sk->n_bitlen + 7) >> 3;

	/*
	 * Decode q.
	 */
	mq = tmp;
	br_i31_decode(mq + fwlen, q, qlen);

	
	br_i31_mulacc(mq, mq + fwlen, r1);
	br_i31_zero(mq + fwlen, fwlen);


	/*
	 * Decode p.
	 */

	t1 = mq + fwlen;

	br_i31_decode(t1 + fwlen, p, plen);
	
	br_i31_mulacc(t1,t1 + fwlen, r2);

	br_i31_zero(t1+fwlen, fwlen);

	/*
	 * Compute the modulus (product of the two factors), to compare
	 * it with the source value. We use br_i31_mulacc(), since it's
	 * already used later on.
	 */

	t2 = mq + 2 * fwlen;
	br_i31_zero(t2, mq[0]);
	br_i31_mulacc(t2, mq, t1);
	
	r = 1;
	xlen = (t2[0] + 7) >> 3;

	/*
	 * We encode the modulus into bytes, to perform the comparison
	 * with bytes. We know that the product length, in bytes, is
	 * exactly xlen.
	 * The comparison actually computes the carry when subtracting
	 * the modulus from the source value; that carry must be 1 for
	 * a value in the correct range. We keep it in r, which is our
	 * accumulator for the error code.
	 */
	/*t3 = mq + 4 * fwlen;
	br_i31_encode(t3, xlen, t2);
	u = xlen;
	r = 0;
	while (u > 0) {
		uint32_t wn, wx;

		u --;
		wn = ((unsigned char *)t3)[u];
		wx = x[u];
		r = ((wx - (wn + r)) >> 8) & 1;
	}
	*/
	/*
	 * Move the decoded p to another temporary buffer.
	 */
	mp = mq + 2 * fwlen;
	memmove(mp, t1, fwlen * sizeof *t1);


	uint32_t a[2];
	mkrand(&rng.vtable, a + 1, 31);
	a[0] = br_i31_bit_length(a +1, 1);
	


	/*
	 * Compute s2 = x^dq mod q.
	 */
	
	uint32_t sqr[2] = {0, 0};
	br_i31_add(sqr, a, 1);


	q0i = br_i31_ninv31(mq[1]);
	s2 = mq + fwlen;
	br_i31_decode_reduce(s2, x, xlen, mq);
	br_i31_decode_reduce(sqr, x, xlen, r1);
	r &= br_i31_modpow_opt(s2, sk->dq, sk->dqlen, mq, q0i,
		mq + 3 * fwlen, TLEN - 3 * fwlen);
	
	uint32_t hlp[2] = {1, 1};
	br_i31_mulacc(s2, a, hlp);
	
	/*
	 * Compute s1 = x^dp mod p.
	 */

	uint32_t spr[2] = {0, 0};
	br_i31_add(spr, a, 1);

	p0i = br_i31_ninv31(mp[1]);
	s1 = mq + 3 * fwlen;
	br_i31_decode_reduce(s1, x, xlen, mp);
	br_i31_decode_reduce(spr, x, xlen, r2);

	r &= br_i31_modpow_opt(s1, sk->dp, sk->dplen, mp, p0i,
		mq + 4 * fwlen, TLEN - 4 * fwlen);
	
	br_i31_mulacc(s1, a, hlp);

	/*
	 * Compute:
	 *   h = (s1 - s2)*(1/q) mod p
	 * s1 is an integer modulo p, but s2 is modulo q. PKCS#1 is
	 * unclear about whether p may be lower than q (some existing,
	 * widely deployed implementations of RSA don't tolerate p < q),
	 * but we want to support that occurrence, so we need to use the
	 * reduction function.
	 *
	 * Since we use br_i31_decode_reduce() for iq (purportedly, the
	 * inverse of q modulo p), we also tolerate improperly large
	 * values for this parameter.
	 */
	t1 = mq + 4 * fwlen;
	t2 = mq + 5 * fwlen;
	br_i31_reduce(t2, s2, mp);
	br_i31_add(s1, mp, br_i31_sub(s1, t2, 1));
	br_i31_to_monty(s1, mp);
	br_i31_decode_reduce(t1, sk->iq, sk->iqlen, mp);
	br_i31_montymul(t2, s1, t1, mp, p0i);

	/*
	 * h is now in t2. We compute the final result:
	 *   s = s2 + q*h
	 * All these operations are non-modular.
	 *
	 * We need mq, s2 and t2. We use the t3 buffer as destination.
	 * The buffers mp, s1 and t1 are no longer needed, so we can
	 * reuse them for t3. Moreover, the first step of the computation
	 * is to copy s2 into t3, after which s2 is not needed. Right
	 * now, mq is in slot 0, s2 is in slot 1, and t2 is in slot 5.
	 * Therefore, we have ample room for t3 by simply using s2.
	 */
	t3 = s2;
	br_i31_mulacc(t3, mq, t2);

	uint32_t one[2] = {1, 1};

	br_i31_add(spr, one, 1);
	br_i31_add(sqr, one, 1);

	uint32_t reduced_x_r1[2] = {0, 0};
	uint32_t reduced_x_r2[2] = {0, 0};

	br_i31_reduce(reduced_x_r1, t3, r1);
	br_i31_reduce(reduced_x_r2, t3, r2);

	br_i31_sub(reduced_x_r1, sqr, 1);
	br_i31_sub(reduced_x_r2, spr, 1);


	uint32_t gama[2];
	br_i31_mulacc(gama, r3, reduced_x_r1);
	
	uint32_t elen = (reduced_x_r1[0] > reduced_x_r2[0])? reduced_x_r1[0] : reduced_x_r2[0];

	uint32_t t4[2] = {0, ( 1u << elen ) - r3[1]};
	t4[0] = br_i31_bit_length(t4 +1, 1);

	br_i31_zero(hlp, hlp[0]);
	br_i31_mulacc(hlp, r3, t4);

	br_i31_add(gama, hlp, 1);
	br_i31_rshift(gama, t4[0]);
	
	// spocitej N -> p * q;
	// udelej a^gama mod N
	// uloz do x t3 - (a^gama mod N)

	/*
	 * Encode the result. Since we already checked the value of xlen,
	 * we can just use it right away.
	 */
	br_i31_encode(x, xlen, t3);

	/*
	 * The only error conditions remaining at that point are invalid
	 * values for p and q (even integers).
	 */
	return p0i & q0i & r;
}
