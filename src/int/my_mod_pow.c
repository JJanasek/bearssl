/*
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org>
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
#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#define U2      (4 + ((BR_MAX_RSA_FACTOR + 30) / 31))
#define TLEN_TMP   (12 * U2)
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


static void print(const uint32_t *x){
	unsigned char buf[1024];
	size_t bit_len = x[0];
    	size_t len = (bit_len + 7)  >> 3;
	br_i31_encode(buf, len, x);
 	
	mpz_t big_int;
	mpz_init(big_int);
	mpz_import(big_int, len, 1, 1, 1, 0, buf);
	char *decimal_str = mpz_get_str(NULL, 10, big_int);
	printf("%s\n", decimal_str);
	mpz_clear(big_int);
	free(decimal_str);
}

static void create_blind(uint32_t *dest, const uint32_t *x, const uint32_t *mod, uint32_t* tmp, uint32_t*rand){
	
	br_i31_zero(tmp, mod[0]);
	tmp[1] = 1;
	//rand[1] |= 1;
	tmp[0] = mod[0];
	br_i31_mulacc(tmp, mod, rand);
	br_i31_zero(dest, tmp[0]);

	br_i31_mulacc(dest, tmp, x);
}


/* see inner.h */
uint32_t
br_i31_modpow_opt_rand(uint32_t *x,
	const unsigned char *e, size_t elen,
	const uint32_t *m, uint32_t m0i, uint32_t *tmp, size_t twlen)
{	
	//printf("\n\n\n");
	size_t mlen, mwlen;
	uint32_t *t1, *t2, *base;
	size_t u, v;
	uint32_t acc;
	int acc_len, win_len;
	uint32_t r[4];
	uint32_t new_m0i;
	uint32_t TMP[TLEN_TMP];
	/*
	 * Get modulus size.
	 */

	
	printf("%d\n", TLEN_TMP);
	/*
	 * RNG init
	 */
	br_hmac_drbg_context rng;
	br_hmac_drbg_init(&rng, &br_sha256_vtable, "seed for RSA BLIND", 18);
	t1 = tmp;
	uint32_t * curr_m = TMP;
	

	mkrand(&rng.vtable, r, 64);
	r[1] ^= ~(r[1]^1) & 0x7FFFFFFF;
	//r[1] |= 1;
	r[0] = br_i31_bit_length(r + 1, 1);
	printf("r:\n");
	print(r);
	

	/*
	 * curr_m = m * (r*m + 1), r is even, m is prime
	 */
	//br_i31_zero(curr_m, m[0]);
	//create_blind(curr_m, m, m, t1, r);
	curr_m = m;
	//br_i31_mulacc(curr_m, m, r);
	m0i = br_i31_ninv31(curr_m[1]);


	mwlen = ((curr_m[0]) + 63 + 64) >> 5;
	mlen = mwlen * sizeof curr_m[0];
	mwlen += (mwlen & 1);
	
	t2 = tmp + mwlen;

	//uint32_t * one = TMP;
	uint32_t * res = TMP + 4 * mwlen;
	uint32_t * new_m = TMP + 8 * mwlen;
	
	br_i31_zero(res, (mlen) << 3);
	memcpy(res + 1, x + 1, (x[0] + 7) >> 3);
	res[0] = x[0];


	br_i31_zero(new_m, curr_m[0]);
	memcpy(new_m+1, curr_m+1, (curr_m[0] + 7) >> 3);
	new_m[0] = curr_m[0];
	new_m0i = m0i;

	int s = (res[0] + 63) >> 5;
	for(;s < mwlen; ++s){
		res[s] = 0;
	}

	res[0] = curr_m[0];
	
	print(curr_m);
	printf("\n");
	
	/*
	 * Compute possible window size, with a maximum of 5 bits.
	 * When the window has size 1 bit, we use a specific code
	 * that requires only two temporaries. Otherwise, for a
	 * window of k bits, we need 2^k+1 temporaries.
	 */
	if (twlen < (mwlen << 1)) {
		return 0;
	}
	for (win_len = 5; win_len > 1; win_len --) {
		if ((((uint32_t)1 << win_len) + 1) * mwlen <= twlen) {
			break;
		}
	}
	printf("winlen: %d\n", win_len);
	/*
	 * Everything is done in Montgomery representation.
	 */
	
	printf("\n");
	print(res);



	br_i31_to_monty(res, curr_m);
	br_i31_from_monty(res, curr_m,  br_i31_ninv31(curr_m[1]));
	print(res);
	br_i31_to_monty(res, curr_m);

	printf("\n");
	/*
	 * Compute window contents. If the window has size one bit only,
	 * then t2 is set to x; otherwise, t2[0] is left untouched, and
	 * t2[k] is set to x^k (for k >= 1).
	 */
	if (win_len == 1) {
		memcpy(t2, res, mlen);
	} else {
		memcpy(t2 + mwlen, res, mlen);
		base = t2 + mwlen;
		for (u = 2; u < ((unsigned)1 << win_len); u ++) {
			/*br_i31_from_monty(x, curr_m, m0i);
			printf("x: ");
			print(x);
			br_i31_to_monty(x, curr_m);
			br_i31_from_monty(base, curr_m, m0i);
			printf("base: ");
			print(base);
			br_i31_to_monty(base, curr_m);*/
			br_i31_montymul(base + mwlen, base, res, curr_m, m0i);
			/*br_i31_from_monty(base + mwlen, curr_m, m0i);
			printf("base + mwlen: ");
			print(base + mwlen);
			br_i31_to_monty(base + mwlen, curr_m);*/
			base += mwlen;
			//printf("\n\n");
		}
	}
	/*
	 * We need to set x to 1, in Montgomery representation. This can
	 * be done efficiently by setting the high word to 1, then doing
	 * one word-sized shift.
	 */
	res[0] = curr_m[0];
	printf("curr_m??:");
	print(curr_m);
	printf("m0i: %d\n", m0i);
	printf("mwlen: %d\n", (curr_m[0] + 31) >> 5);

	br_i31_zero(res, curr_m[0]);
	res[(curr_m[0] + 31) >> 5] = 1;
	print(res);
	printf("%d, %d\n", curr_m[0], res[0]);
	br_i31_muladd_small(res, 0, curr_m);
	print(res);
	
	res[0] = curr_m[0];
	br_i31_from_monty(res, curr_m, br_i31_ninv31(curr_m[1]));
	printf("IS IT ONE???:");
	print(res);
	br_i31_to_monty(res, curr_m);
	/*
	 * We process bits from most to least significant. At each
	 * loop iteration, we have acc_len bits in acc.
	 */
	acc = 0;
	acc_len = 0;
	
	while (acc_len > 0 || elen > 0) {
		int i, k;
		uint32_t bits;

		/*
		 * Get the next bits.
		 */
		k = win_len;
		if (acc_len < win_len) {
			if (elen > 0) {
				acc = (acc << 8) | *e ++;
				elen --;
				acc_len += 8;
			} else {
				k = acc_len;
			}
		}
		bits = (acc >> (acc_len - k)) & (((uint32_t)1 << k) - 1);
		acc_len -= k;

		/*
		 * Here we re-randomize modulus as (m * r)
		 */
		printf("x: ");
		print(res);
		printf("\n");
		for(int i = 0; i < (res[0] + 63) >> 5; ++i){
			printf("%d,",res[i]);
		}
		printf("\n");
		printf("mod: ");
		//print(curr_m);
		for(int i = 0; i < (curr_m[0] + 63) >> 5; ++i){
			printf("%d,",curr_m[i]);
		}
		printf("\n");


		mkrand(&rng.vtable, r, 64);
		r[1] ^= ~(r[1]^1) & 0x7FFFFFFF;
		r[0] = br_i31_bit_length(r + 1, 1);
		printf("r:\n");
		print(r);
		
		//create_blind(new_m, curr_m, curr_m, t1, r);
		//new_m0i = br_i31_ninv31(new_m[1]);


		/*
		 * We could get exactly k bits. Compute k squarings.
		 */
		for (i = 0; i < k; i ++) {
			br_i31_montymul(t1, res, res, new_m, new_m0i);
			memcpy(res, t1, mlen);
			printf("x^(2^k):");
			print(res);
		}




		/*
		 * Window lookup: we want to set t2 to the window
		 * lookup value, assuming the bits are non-zero. If
		 * the window length is 1 bit only, then t2 is
		 * already set; otherwise, we do a constant-time lookup.
		 */
		if (win_len > 1) {
			br_i31_zero(t2, new_m[0]);
			base = t2 + mwlen;
			for (u = 1; u < ((uint32_t)1 << k); u ++) {
				uint32_t mask;

				mask = -EQ(u, bits);
				for (v = 1; v < mwlen; v ++) {
					t2[v] |= mask & base[v];
				}
				base += mwlen;
			}
		}

		/*
		 * Multiply with the looked-up value. We keep the
		 * product only if the exponent bits are not all-zero.
		 */

		
		printf("t2: ");
		print(t2);
		printf("\n");
		for(int i = 0; i < (t2[0] + 63) >> 5; ++i){
			printf("%d,",t2[i]);
		}
		printf("\n");
		printf("\n");
		
		


		uint32_t* mask_res = new_m + 2 * mwlen;
		create_blind(mask_res, res, new_m, t1, r);
		
		uint32_t* mask_t2 = new_m + 4 * mwlen;
		create_blind(mask_t2, t2, new_m, t1, r);
		printf("mask_res: ");
		print(mask_res);
		printf("\n");
		for(int i = 0; i < (mask_res[0] + 63) >> 5; ++i){
			printf("%d,",mask_res[i]);
		}
		printf("\n");
		printf("mask_rt2: ");
		printf("\n");
		print(mask_t2);
		printf("\n");
		for(int i = 0; i < (mask_t2[0] + 63) >> 5; ++i){
			printf("%d,",mask_t2[i]);
		}
		printf("\n");


		printf("\n");
		


		br_i31_montymul(t1, t2, res, new_m,  new_m0i);

		//printf("AFTER MUL\n");
		//printf("AFTER t1: ");
		//print(t1);
		//printf("AFTER x: ");
		//print(res);

		CCOPY(NEQ(bits, 0), res, t1, mlen);

		//printf("COPY x: ");
		//print(res);
		
	}

	/*
	 * Convert back from Montgomery representation, and exit.
	 */
	br_i31_from_monty(res, curr_m, m0i);
	//print(x);
	br_i31_reduce(x,res,m);

	return 1;
}

