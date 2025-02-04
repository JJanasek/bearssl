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

#include "bearssl.h"
#include "inner.h"
#define U      (2 + ((BR_MAX_RSA_FACTOR + 30) / 31))
#define TLEN   (36 * U)

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


static size_t blind_exponent( const br_prng_class ** rng, unsigned char * x, const unsigned char* d, const size_t size, uint32_t * m, uint32_t * t1){

	uint32_t r[(BR_RSA_RAND_FACTOR + 63) >> 5];
    	mkrand(rng, r, BR_RSA_RAND_FACTOR);
	r[0] = br_i31_bit_length(r + 1, (BR_RSA_RAND_FACTOR + 31) >> 5);
	
	br_i31_zero(t1, m[0]);
	br_i31_decode(t1, d, size);
	t1[0] = m[0];
		
	size_t xlen = (m[0] + 7) >> 3; 
	// store in t1 = d + r * phi(m)
	br_i31_mulacc(t1, m, r);
	xlen = (t1[0] + 7) >> 3;
	
	br_i31_encode(x, xlen, t1);
	return xlen;
}


static void reblind(uint32_t * dest, uint32_t * src, uint32_t* mod, uint32_t * new_mask, uint32_t* tmp_buf){
    
	br_i31_zero(tmp_buf, 2* mod[0]);
    	tmp_buf[0] = new_mask[0];
	br_i31_mulacc(tmp_buf, new_mask, src);
 	br_i31_zero(dest, mod[0]);
	br_i31_reduce(dest, tmp_buf, mod);
	dest[0] = br_i31_bit_length(dest + 1, (dest[0] + 31) >> 5);
}

static void inverse(uint32_t * dest, uint32_t * src, uint32_t * mod, uint32_t * tmp){
	br_i31_zero(dest, mod[0]);
	src[0] = mod[0];
	dest[1] = 1;
	br_i31_moddiv(dest, src, mod, br_i31_ninv31(mod[1]), tmp);
}

static void create_mask(uint32_t * dest, uint32_t * m,uint32_t *op1,uint32_t * op2, uint32_t * tmp_buf){
	br_i31_zero(tmp_buf, m[0]);
	br_i31_mulacc(tmp_buf, op1, op2);
	br_i31_reduce(dest, tmp_buf, m);
}


static void init_key( const br_prng_class ** rng, const br_rsa_private_key *sk, br_rsa_private_key *new_sk, uint32_t *tmp, uint32_t fwlen){

	// copy public modulus
	memcpy(new_sk->n, sk->n, (sk->n_bitlen +7) >> 3);
	new_sk->n_bitlen = sk->n_bitlen;
	
	// create random mask r1
    mkrand(rng, new_sk->r1, BR_RSA_RAND_FACTOR);
	new_sk->r1[1] |= 1;
	new_sk->r1[0] = br_i31_bit_length(new_sk->r1 + 1, (BR_RSA_RAND_FACTOR + 31) >> 5);
	
	// create random mask r2
    mkrand(rng, new_sk->r2, BR_RSA_RAND_FACTOR);
	new_sk->r2[1] |= 1;
	new_sk->r2[0] = br_i31_bit_length(new_sk->r2 + 1, (BR_RSA_RAND_FACTOR + 31) >> 5);

	uint32_t * t1 = tmp + fwlen;
	

	br_i31_decode(tmp, sk->p, sk->plen);
	
	// blind phi(p)
	tmp[1] ^= 1;
	br_i31_zero(new_sk->phi_p, tmp[0]);
	br_i31_mulacc(new_sk->phi_p, tmp, new_sk->r1);
	tmp[1] ^= 1;

	// blind p
	br_i31_zero(t1, tmp[0]);
	br_i31_mulacc(t1, tmp, new_sk->r1);
    t1[0] = br_i31_bit_length(t1 + 1, (t1[0] + 31) >> 5);
	br_i31_encode(new_sk->p, (t1[0] + 7) >> 3, t1);
	new_sk->plen = (t1[0] + 7) >> 3;
	
	br_i31_decode(tmp, sk->q, sk->qlen);
	
	// blind phi(q)
	tmp[1] ^= 1;
	br_i31_zero(new_sk->phi_q, tmp[0]);
	br_i31_mulacc(new_sk->phi_q, tmp, new_sk->r2);
	tmp[1] ^= 1;
	
	// blind q
	br_i31_zero(t1, tmp[0]);
	br_i31_mulacc(t1, tmp, new_sk->r2);
    t1[0] = br_i31_bit_length(t1 + 1, (t1[0] + 31) >> 5);
	br_i31_encode(new_sk->q, (t1[0] + 7) >> 3, t1);
	new_sk->qlen = (t1[0] + 7) >> 3;
	

	br_i31_decode(tmp, new_sk->n, (new_sk->n_bitlen + 7) >> 3);
	t1 = tmp + 2 * fwlen;
	uint32_t *t2 = t1 + 2 * fwlen;

	// inverse of random factor r_2 mod n
	br_i31_zero(t1, tmp[0]);
	memcpy(t1 + 1, new_sk->r2 + 1, (new_sk->r2[0] + 7) >> 3);
	inverse(t2, t1, tmp, t2 + 2*fwlen);

	// blind qinv
	br_i31_decode(tmp, new_sk->p, new_sk->plen);
	br_i31_reduce(t1, t2, tmp);
    
    uint32_t * t3 = t2 + 2 * fwlen;
	
    br_i31_decode_reduce(t2, sk->iq, sk->iqlen,tmp);
    reblind(t2, t1, tmp, t2, t3);
	br_i31_encode(new_sk->iq, (t2[0] + 7) >> 3, t2);
	new_sk->iqlen = (t2[0] + 7) >> 3;
    
	memcpy(new_sk->dp, sk->dp, sk->dplen);
	memcpy(new_sk->dq, sk->dq, sk->dqlen);
	memcpy(new_sk->e, sk->e, sk->elen);
	new_sk->dplen = sk->dplen;
	new_sk->dqlen = sk->dqlen;
	new_sk->elen = sk->elen;
}




static void update_key( const br_prng_class ** rng, br_rsa_private_key *new_sk, uint32_t *tmp, uint32_t fwlen ){

	uint32_t * r1_inv = tmp;
	uint32_t * r2_inv = tmp + 2 * fwlen;
	uint32_t * t1 = r2_inv + 2 * fwlen;
	uint32_t * mod = t1 + 2 * fwlen;
	uint32_t * t3 = mod + 2 * fwlen;
	uint32_t * t4 = t3 + 2 * fwlen;


	br_i31_decode(mod, new_sk->n, (new_sk->n_bitlen + 7) >> 3);


	// calculating multiplicative inverse of r_1
	br_i31_zero(t1, mod[0]);
	memcpy(t1 + 1, new_sk->r1 + 1, (new_sk->r1[0] + 7) >> 3);
	inverse(r1_inv, t1, mod, t3);
	

	// generating new value for r_1
    mkrand(rng, new_sk->r1, BR_RSA_RAND_FACTOR);
	new_sk->r1[1] |= 1;
	new_sk->r1[0] = br_i31_bit_length(new_sk->r1 + 1, (BR_RSA_RAND_FACTOR + 31) >> 5);
	
    // storing old random factor, later used in mask for qinv	
	uint32_t temp_r2[(BR_RSA_RAND_FACTOR + 63) >> 5];
	memcpy(temp_r2 + 1, new_sk->r2 + 1, (new_sk->r2[0] + 7) >> 3);
	temp_r2[0] = new_sk->r2[0];

	// generating new value for r_2
    mkrand(rng, new_sk->r2, BR_RSA_RAND_FACTOR);
	new_sk->r2[1] |= 1;
	new_sk->r2[0] = br_i31_bit_length(new_sk->r2 + 1, (BR_RSA_RAND_FACTOR + 31) >> 5);
	
	
	// re-blinding p
	br_i31_decode(t1, new_sk->p, new_sk->plen);
	create_mask(t3, mod, new_sk->r1, r1_inv, t4);
	reblind(t3, t1, mod, t3, t4);
	br_i31_encode(new_sk->p, (t3[0] + 7) >> 3, t3);
	new_sk->plen = (t3[0] + 7) >> 3;

	// re-blinding phi(p)
	create_mask(t1, mod, r1_inv, new_sk->r1, t3);
	reblind(t1, new_sk->phi_p, mod, t1, t3);
	br_i31_zero(new_sk->phi_p, mod[0] >> 1);
	memcpy(new_sk->phi_p + 1, t1 + 1, (t1[0] + 7) >> 3);
	new_sk->phi_p[0] = t1[0];
	
	// calculating multiplicative inverse of old r_2
	br_i31_zero(t1, mod[0]);
	memcpy(t1 + 1, temp_r2 + 1, (temp_r2[0] + 7) >> 3);
	inverse(r2_inv, t1, mod, t3);
	

	// re-blinding phi(q)
	create_mask(t1, mod, new_sk->r2, r2_inv, t3);
    reblind(t1, new_sk->phi_q, mod, t1, t3);
	br_i31_zero(new_sk->phi_q, mod[0] >> 1);
	memcpy(new_sk->phi_q + 1, t1 + 1, (t1[0] + 7) >> 3);
	new_sk->phi_q[0] = t1[0];
	
	
	// re-blinding q
	br_i31_decode(t1, new_sk->q, new_sk->qlen);
	create_mask(t3, mod, new_sk->r2, r2_inv, t4);
	reblind(t3, t1, mod, t3, t4);
	br_i31_encode(new_sk->q, (t3[0] + 7) >> 3, t3);
	new_sk->qlen = (t3[0] + 7) >> 3;
	
	// calculating multiplicative inverse of new r_2
	br_i31_zero(t1, mod[0]);
	memcpy(t1 + 1, new_sk->r2 + 1, (new_sk->r2[0] + 7) >> 3);
	inverse(r2_inv, t1, mod, t3);
		
	// blinding qinv
	br_i31_decode(mod, new_sk->p, new_sk->plen);
	br_i31_decode(t1, new_sk->iq, new_sk->iqlen);
	create_mask(t3, mod, temp_r2, r2_inv, t4);
	reblind(t3, t1, mod, t3, t4);
	br_i31_encode(new_sk->iq, (t3[0] + 7) >> 3, t3);
	new_sk->iqlen = (t3[0] + 7) >> 3;


}

/* see bearssl_rsa.h */
uint32_t
br_rsa_i31_private_mod_prerand(unsigned char *x, const br_rsa_private_key *sk)
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
	fwlen =  1 + 18;
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



	br_rsa_private_key rsa_sk;
	mq = tmp;
	uint32_t r2[(BR_RSA_RAND_FACTOR + 63) >> 5];
	uint32_t r3[(BR_RSA_RAND_FACTOR + 63) >> 5];
	uint32_t phi_p[(BR_MAX_RSA_SIZE + BR_RSA_RAND_FACTOR +  63) >> 5];
	uint32_t phi_q[(BR_MAX_RSA_SIZE + BR_RSA_RAND_FACTOR + 63) >> 5];
	unsigned char n_buf[(BR_MAX_RSA_SIZE + 15) >> 3];
	unsigned char p_buf[(BR_MAX_RSA_SIZE + BR_RSA_RAND_FACTOR + 15) >> 3];
	unsigned char q_buf[(BR_MAX_RSA_SIZE + BR_RSA_RAND_FACTOR + 15) >> 3];
	unsigned char dp_buf[(BR_MAX_RSA_SIZE + 15) >> 3];
	unsigned char dq_buf[(BR_MAX_RSA_SIZE + 15) >> 3];
	unsigned char iq_buf[(BR_MAX_RSA_SIZE + 15) >> 3];
	unsigned char e_buf[(BR_MAX_RSA_SIZE + 15) >> 3];
	rsa_sk.r1 = r2;
	rsa_sk.r2 = r3;
	rsa_sk.n = n_buf;
	rsa_sk.p = p_buf;
	rsa_sk.q = q_buf;
	rsa_sk.dp = dp_buf;
	rsa_sk.dq = dq_buf;
	rsa_sk.iq = iq_buf;
	rsa_sk.phi_p = phi_p;
	rsa_sk.phi_q = phi_q;
	rsa_sk.e = e_buf;
    

	br_hmac_drbg_context rng;
	br_hmac_drbg_init(&rng, &br_sha256_vtable, "seed for RSA SAFE", 17);
	
	init_key(&rng.vtable, sk, &rsa_sk, tmp, fwlen);

    update_key(&rng.vtable, &rsa_sk, tmp, fwlen);
    
	uint32_t r1[(BR_RSA_RAND_FACTOR + 63) >> 5];
	mkrand(&rng.vtable, r1, BR_RSA_RAND_FACTOR);
	r1[0] = br_i31_bit_length(r1 + 1, (BR_RSA_RAND_FACTOR + 31) >> 5);
	

	/*
	 * Decode q.
	 */

	mq = tmp;

	/*
	 * Decode p.
	 */
	
	t1 = mq + fwlen;
	
	/*
	 * Compute the modulus (product of the two factors), to compare
	 * it with the source value. We use br_i31_mulacc(), since it's
	 * already used later on.
	 */
	
	t2 = mq + 2 * fwlen;
	br_i31_zero(t2, mq[0]);
	br_i31_decode(t2, rsa_sk.n, (rsa_sk.n_bitlen + 7) >> 3);
	//br_i31_mulacc(t2, mq, t1);
	uint32_t len = br_i31_bit_length(t2 , (t2[0] + 63) >> 5);
	if(t2[0] + 32 > len){
		t2[0] = len - 32;
	}
	else{
		t2[0] = t2[0];
	}
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
	 * Compute (r^e * C) (mod n)
	 */	
	
	uint32_t *n = t2;
	br_i31_decode(n, rsa_sk.n, (rsa_sk.n_bitlen + 7) >> 3);
	uint32_t *c = t3;
	uint32_t *c_prime = mq + 6 * fwlen;
	uint32_t * r_to_e = mq;	
	
	br_i31_zero(c, n[0]);
	br_i31_decode_reduce(c, x, xlen, n);
	
	br_i31_zero(r_to_e, n[0]);
	memcpy(r_to_e + 1, r1 + 1,  ((*r1 + 7) >> 3));
	r_to_e[0] = n[0];

	r &= br_i31_modpow_opt(r_to_e, rsa_sk.e, rsa_sk.elen, n,  br_i31_ninv31(n[1]), mq + 8 * fwlen, TLEN - 8 * fwlen);

	br_i31_zero(c_prime, n[0]);
	c[0] = c_prime[0];
	br_i31_mulacc(c_prime, c, r_to_e);
	
	mq = tmp + 4 * fwlen;
	mp = tmp + 5 * fwlen;


	br_i31_decode(mq,  rsa_sk.q,  rsa_sk.qlen);
	br_i31_decode(mp,  rsa_sk.p,  rsa_sk.plen);
    
	s2 = tmp;
	s1 = tmp + fwlen;
	/*
	 * store C' = r^e * C in s1 (mod p)
	 * store C' = r^e * C in s2 (mod q)
	 */

	
	br_i31_reduce(s1, c_prime, mp);
	br_i31_reduce(s2, c_prime, mq);
	

	
	/*
	 * Move the decoded p to another temporary buffer.
	 */

	
	unsigned char* dq = (unsigned char *) (tmp + 6 *fwlen); 
	size_t dqlen = blind_exponent(&rng.vtable, dq, rsa_sk.dq, rsa_sk.dqlen, rsa_sk.phi_q, tmp + 7 * fwlen);

		
	/*
	 * Compute s2 = x^dq mod q.
	 */
	q0i = br_i31_ninv31(mq[1]);

	
	r &= br_i31_modpow_opt_rand(&rng.vtable, s2, dq, dqlen, mq, q0i,
		tmp + 7 * fwlen, TLEN - 7 * fwlen);
	
	/*
	 * Compute s1 = x^dp mod p.
	 */
	
	unsigned char* dp = (unsigned char *) (tmp + 6 *fwlen); 
	size_t dplen = blind_exponent(&rng.vtable, dp, rsa_sk.dp, rsa_sk.dplen, rsa_sk.phi_p, tmp + 7 * fwlen);

	
	p0i = br_i31_ninv31(mp[1]);
	
	r &= br_i31_modpow_opt_rand(&rng.vtable, s1, dp, dplen, mp, p0i,
		tmp + 8 * fwlen, TLEN - 8 * fwlen);
	
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


	t1 = tmp + 6 * fwlen;
	t2 = tmp + 8 * fwlen;
	br_i31_reduce(t2, s2, mp); 
	br_i31_add(s1, mp, br_i31_sub(s1, t2, 1));
	br_i31_to_monty(s1, mp);
	br_i31_decode_reduce(t1,  rsa_sk.iq,  rsa_sk.iqlen, mp);
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
	
	t1 = tmp + 4 * fwlen;
	br_i31_zero(t1, n[0]);
	br_i31_reduce(t1, t3, n); 
	

	t2 = tmp + 6 * fwlen;
	br_i31_zero(t2, n[0]);
	memcpy(t2 + 1, r1 + 1, (*r1 + 7) >> 3);
	t2[0] = n[0];
	t1[0] = n[0];
	
	r &= br_i31_moddiv(t1, t2, n, br_i31_ninv31(n[1]), tmp + 8 * fwlen);
	
	/*
	 * Encode the result. Since we already checked the value of xlen,
	 * we can just use it right away.
	 */
	

	br_i31_encode(x, xlen, t1);


	/*
	 * The only error conditions remaining at that point are invalid
	 * values for p and q (even integers).
	 */
	return p0i & q0i & r;
}
