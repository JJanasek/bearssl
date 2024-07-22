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


static uint32_t compute_phi(uint32_t in){
	
	uint64_t r = in;
	uint32_t p = 2;

	while ( p <= in ){
		
		if ( in % p == 0){
			r *= p - 1;
			r /= p;		
		}

		while ( in % p == 0){
			in /= p;
		}
	
		++ p; 
	}

	return r;

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

        br_hmac_drbg_init(&rng, &br_sha256_vtable, "seed for RSA SAFE", 17);	
	/*
	 * Create small random numbers r1, r2, r3
	 */

        uint32_t r1[2], r2[2], r3[2];	
	
	mkrand(&rng.vtable, r1, 4);
	mkrand(&rng.vtable, r2, 4);
	mkrand(&rng.vtable, r3, 4);

	r2[1] |= 1;
	r1[1] |= 1;
	
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
	 * We need to fit at least 8 values in the stack buffer.
	 */
	if (8 * fwlen > TLEN) {
		return 0;
	}

	/*
	 * Compute modulus length (in bytes).
	 */
	xlen = (sk->n_bitlen + 7) >> 3;

	/*
	 * Decode q.
	 */

	/* 
	 * tmp [mq, q, ....]
	 */

	mq = tmp;
	br_i31_zero(mq, fwlen <<  5);
	br_i31_decode(mq + fwlen, q, qlen);

	/*
	 * tmp [mq + q * r1, ...]
	 */
	
	br_i31_mulacc(mq, mq + fwlen, r1);
	br_i31_zero(mq + fwlen, fwlen << 5);


	/*
	 * Decode p.
	 */

	/*	 mq        
	 * tmp [q * r1, t1 ,p, ...]
	 */

	t1 = mq + fwlen;
	br_i31_decode(t1 + fwlen, p, plen);
	
	/*
	 * tmp [q * r1, t1 + p * r2, ... ]
	 */
	
	br_i31_mulacc(t1,t1 + fwlen, r2);
	br_i31_zero(t1+fwlen, fwlen << 5);

	/*
	 * Compute the modulus (product of the two factors), to compare
	 * it with the source value. We use br_i31_mulacc(), since it's
	 * already used later on.
	 */
	

	/*
	 * tmp [q *r1, p * r2, q*r1 * p*r2, ... ]
	 */

	t2 = mq + 2 * fwlen;
	br_i31_zero(t2, mq[0]);
	br_i31_mulacc(t2, mq, t1);
	
	r = 1;

	/*
	 * We encode the modulus into bytes, to perform the comparison
	 * with bytes. We know that the product length, in bytes, is
	 * exactly xlen.
	 * The comparison actually computes the carry when subtracting
	 * the modulus from the source value; that carry must be 1 for
	 * a value in the correct range. We keep it in r, which is our
	 * accumulator for the error code.
	 */
	t3 = mq + 4 * fwlen;
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
	
	/*
	 * Move the decoded p to another temporary buffer.
	 */


	/*
	 * tmp [ q *r1, ..., p*r2, ... ]
	 */

	mp = mq + 2 * fwlen;
	memmove(mp, t1, fwlen * sizeof *t1);


	uint32_t a[2];
	mkrand(&rng.vtable, a, 4);
	a[0] = br_i31_bit_length(a + 1, 1);
	

	uint32_t one[2] = {1, 1};

	/*
	 * Compute s2 = x^dq mod q.
	 */
	
	q0i = br_i31_ninv31(mq[1]);
	s2 = mq + fwlen;
	br_i31_decode_reduce(s2, x, xlen, mq);	
	r &= br_i31_modpow_opt(s2, sk->dq, sk->dqlen, mq, q0i,
		mq + 3 * fwlen, TLEN - 3 * fwlen);
	
	br_i31_mulacc(s2, a, one);
	
	/*
	 * tmp [q * r1, (m (mod q * r1) )^dp  + a * 1, p * r2, ...]
	 */
		
	
	/*
	 * Compute sqr = x^dq mod r1
	 */

	uint32_t sqr[2] = {0, 0};
	uint32_t r10i = br_i31_ninv31(r1[1]);
	uint32_t phi[2] = {0, compute_phi(r1[1])};

	phi[0] = br_i31_bit_length(phi +1, 1);
	uint32_t dq[2];
		
	br_i31_decode_reduce(dq, sk->dq, sk->dqlen, phi);
	br_i31_decode_reduce(sqr, x, xlen, r1);
	
	br_enc32be(dq + 1, *(dq + 1));
	dq[0] = br_i31_bit_length(dq +1, 1);
	
	r &= br_i31_modpow_opt(sqr, (const unsigned char *)(dq + 1), (dq[0] + 7) >> 3, r1, r10i, mq + 3 * fwlen, TLEN - 3 * fwlen);
	br_i31_mulacc(sqr, a, one);


	/*
	 * Compute s1 = x^dp mod p.
	 */

	p0i = br_i31_ninv31(mp[1]);
	s1 = mq + 3 * fwlen;
	br_i31_decode_reduce(s1, x, xlen, mp);

	r &= br_i31_modpow_opt(s1, sk->dp, sk->dplen, mp, p0i,
		mq + 4 * fwlen, TLEN - 4 * fwlen);
	br_i31_mulacc(s1, a, one);


	
	/*
	 * Compute spr = x^dp mod r2
	 */

	uint32_t spr[2] = {0, 0};
	uint32_t r20i = br_i31_ninv31(r2[1]);
	phi[1] = compute_phi(r2[1]);

	phi[0] = br_i31_bit_length(phi +1, 1);
	uint32_t dp[2];
		
	br_i31_decode_reduce(dp, sk->dp, sk->dplen, phi);
	br_i31_decode_reduce(spr, x, xlen, r2);
	
	br_enc32be(dp + 1, *(dp + 1));
	dp[0] = br_i31_bit_length(dp +1, 1);
	
	r &= br_i31_modpow_opt(spr, (const unsigned char *) (dp + 1), (dp[0] + 7) >> 3 , r2, r20i, mq + 4 * fwlen, TLEN - 4 * fwlen);
	br_i31_mulacc(spr, a, one);
	

	/*
	 * Compute iq'
	 */
	uint32_t * iq = mq + 4 * fwlen;
	br_i31_zero(iq, fwlen << 5);
	iq[1] = 1;
	br_i31_moddiv(iq, mq, mp, br_i31_ninv31(mp[1]), iq + fwlen);
	
	
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
	
	//t1 = mq + 5 * fwlen;
	t2 = mq + 5 * fwlen;
	br_i31_reduce(t2, s2, mp);
	br_i31_add(s1, mp, br_i31_sub(s1, t2, 1));
	br_i31_to_monty(s1, mp);
	
	//br_i31_decode_reduce(t1, sk->iq, sk->iqlen, mp);
	
	br_i31_montymul(t2, s1, iq, mp, p0i);
	//br_i31_from_monty(t2, mp, p0i);

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



	 /*
	  * c1 = S' - Sqr + 1 mod r1
	  * c2 = S' - Spr + 1 mod r2
	  */

	 uint32_t c1[2] = {0,0};
	 uint32_t c2[2] = {0,0};

	 br_i31_reduce(c1, t3, r1);
	 br_i31_reduce(c2, t3, r2);
	 
	 uint32_t hlp[2];
	 br_i31_reduce(hlp, sqr, r1);
	 br_i31_sub(c1, hlp, 1);
	 
	 br_i31_reduce(hlp, spr, r2);
	 br_i31_sub(c2, hlp, 1);

	
	 br_i31_add(c1, one, 1);
	 br_i31_add(c2, one, 1);

	 c1[0] = br_i31_bit_length(c1 + 1, 1);
	 c2[0] = br_i31_bit_length(c2 + 1, 1);
	 uint32_t l = (c1[0] > c2[0])? c1[0] : c2[0];
	
	 /*
	  * gama = (r3 * c1 + (2^l - r3) * c2) / 2^l
	  */
	
	 uint32_t gama[2] = {0,0};
	 hlp[1] = 1 << l;
	 hlp[0] = l;

	 br_i31_mulacc(gama, c1, r3);
	 br_i31_sub(hlp, r3, 1);
	 br_i31_mulacc(gama, c2, hlp);
	 br_i31_rshift(gama, l);
	
	 
	br_enc32be(gama + 1, *(gama + 1));
	gama[0] = br_i31_bit_length(gama +1, 1);
	/*
	 * Encode the result. Since we already checked the value of xlen,
	 * we can just use it right away.
	 */
	
	/*
	 * Compute N = p * q
	 */

	 br_i31_decode(mq, sk->q, sk->qlen);
	 br_i31_decode(mq + 3 * fwlen, sk->p, sk->plen);
	 mp = mq + 3 * fwlen;

	 br_i31_zero(mq + 4 * fwlen, (2*fwlen) << 5);
	 br_i31_mulacc(mq + 4 *fwlen, mq, mp);
	
	 memmove(mq, t3, 2 * fwlen * sizeof *mq);
 	 memmove(mq + 2 * fwlen,  mq + 4 *fwlen, 2 * fwlen * sizeof *mq);	 
	 uint32_t * N = mq + 2 * fwlen;

	 t2 = N + 2 * fwlen;
	 memmove(t2, a, 2 * sizeof a[0]);

	 br_i31_modpow_opt(t2, (unsigned char*)(gama + 1), (gama[0] + 7) >> 3, N, br_i31_ninv31(N[1]),  t2 + 2 * fwlen, TLEN  - 6*fwlen);
	 br_i31_sub(t3, t2, 1);
	 br_i31_reduce(mq+4*fwlen, t3, N); 
	

	 br_i31_encode(x, xlen, mq+4*fwlen);

	/*
	 * The only error conditions remaining at that point are invalid
	 * values for p and q (even integers).
	 */
	return p0i & q0i & r;
}
