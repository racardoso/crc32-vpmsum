/*
 * vec_final_fold.c
 * Author: rcardoso
 * Author: sjmunroe
 * Created on: May 13, 2017
 * TODO: License
 *
 */

#include <altivec.h>

#if defined(__LITTLE_ENDIAN__)
static const __vector unsigned long long v_fold2_const[4]
	__attribute__ ((aligned (16))) = {
		/* x^128 mod p(x), x^96 mod p(x), x^64 mod p(x), x^32 mod p(x) */
		{ 0x490d678d04c11db7UL, 0xe8a45605f200aa66UL },
		/* Barrett constant m - (4^32)/n */
		{ 0x0000000104d101dfUL, 0x0000000000000000UL },
		/* Barrett constant n */
		{ 0x0000000104c11db7UL, 0x0000000000000000UL },
		/* byte reverse permute constant, in LE order */
		{ 0x08090A0B0C0D0E0FUL, 0x0001020304050607UL }
	};

static const __vector unsigned long long v_fold2_reflect_const[4]
	__attribute__ ((aligned (16))) = {
		/* x^32 mod p(x)`, x^64 mod p(x)`, x^96 mod p(x)`, x^128 mod p(x)` */
		{ 0x6655004fa06a2517UL, 0xedb88320b1e6b092UL },
		/* 33 bit reflected Barrett constant m - (4^32)/n */
		{ 0x00000001f7011641UL, 0x0000000000000000UL },
		/* 33 bit reflected Barrett constant n */
		{ 0x00000001db710641UL, 0x0000000000000000UL },
		/* byte reverse permute constant, in LE order */
		{ 0x08090A0B0C0D0E0FUL, 0x0001020304050607UL }
	};
#else
static const __vector unsigned long long v_fold2_const[4]
	 __attribute__ ((aligned (16))) = {
		/* x^128 mod p(x), x^96 mod p(x), x^64 mod p(x), x^32 mod p(x) */
		{ 0xe8a45605f200aa66UL, 0x490d678d04c11db7UL },
		/* Barrett constant m - (4^32)/n */
		{ 0x0000000000000000UL, 0x0000000104d101dfUL },
		/* Barrett constant n */
		{ 0x0000000000000000UL, 0x0000000104c11db7UL },
		/* byte reverse permute constant, in BE order */
		{ 0x0F0E0D0C0B0A0908UL, 0X0706050403020100UL }
	};

static const __vector unsigned long long v_fold2_reflect_const[4]
	__attribute__ ((aligned (16))) = {
		/* x^32 mod p(x)`, x^64 mod p(x)`, x^96 mod p(x)`, x^128 mod p(x)` */
		{ 0xedb88320b1e6b092UL, 0x6655004fa06a2517UL },
		/* 33 bit reflected Barrett constant m - (4^32)/n */
		{ 0x0000000000000000UL, 0x00000001f7011641UL },
		/* 33 bit reflected Barrett constant n */
		{ 0x0000000000000000UL, 0x00000001db710641UL },
		/* byte reverse permute constant, in BE order */
		{ 0x0F0E0D0C0B0A0908UL, 0X0706050403020100UL }
	};
#endif

unsigned long  __attribute__ ((aligned (32)))
final_fold2(void *__restrict__ data) {

	const __vector unsigned long long vzero = {0,0};
	const __vector unsigned long long vones = {0xffffffffffffffffUL,
												0xffffffffffffffffUL};

	const __vector unsigned long long vmask_64bit =
		(__vector unsigned long long)vec_sld((__vector unsigned char)vzero,
			(__vector unsigned char)vones, 8);

	__vector unsigned long long vconst1 = vec_ld(0, v_fold2_const);
	__vector unsigned long long vconst2 = vec_ld(16, v_fold2_const);
	__vector unsigned long long vconst3 = vec_ld(32, v_fold2_const);

	__vector unsigned long long vdata, v0, v1;

	unsigned long result = 0;

	vdata = vec_ld(0, (__vector unsigned long long*) data);
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__vector unsigned long long vconstp = vec_ld(48, v_fold2_const);
	vdata = vec_perm (vdata, vdata, (__vector unsigned char)vconstp);
#endif

	v0 = (__vector unsigned long long)__builtin_crypto_vpmsumw (
			(__vector unsigned int)vdata, (__vector unsigned int)vconst1);
	/* xor two 64 bit results together */
	v1 = (__vector unsigned long long)vec_sld((__vector unsigned char)v0,
			(__vector unsigned char)v0, 8);
	v0 = vec_xor (v1, v0);
	v0 = vec_and (v0, vmask_64bit);

	/*
	 * Now for Barrett reduction. The idea is to calculate q,
	 * the multiple of our polynomial that we need to subtract. By
	 * doing the computation 2x bits higher (ie 64 bits) and shifting the
	 * result back down 2x bits, we round down to the nearest multiple.
	 */
	/* ma */
	v1 = __builtin_crypto_vpmsumd ((__vector unsigned long long)v0,
			(__vector unsigned long long)vconst2);
	/* q = floor(ma/(2^64)) */
	v1 = (__vector unsigned long long)vec_sld ((__vector unsigned char)vzero,
			(__vector unsigned char)v1, 8);
	/* qn */
	v1 = __builtin_crypto_vpmsumd ((__vector unsigned long long)v1,
			(__vector unsigned long long)vconst3);
	 /* a - qn, subtraction is xor in GF(2) */
	v0 = vec_xor (v1, v0);
	/*
	 * Get the result into r3. We need to shift it left 8 bytes:
	 * V0 [ 0 1 2 X ]
	 * V0 [ 0 X 2 3 ]
	 */
	result = __builtin_unpack_vector_int128 ((vector __int128_t)v0, 1);

	return result;
}

unsigned long  __attribute__ ((aligned (32)))
final_fold2_reflected(void *__restrict__ data) {
	const __vector unsigned long long vzero = {0,0};
	const __vector unsigned long long vones = {0xffffffffffffffffUL,
												0xffffffffffffffffUL};
	const __vector unsigned long long vmask_32bit =
		(__vector unsigned long long)vec_sld((__vector unsigned char)vzero,
			(__vector unsigned char)vones, 4);
	const __vector unsigned long long vmask_64bit =
		(__vector unsigned long long)vec_sld((__vector unsigned char)vzero,
			(__vector unsigned char)vones, 8);

    __vector unsigned long long vconst1 = vec_ld(0, v_fold2_reflect_const);
    __vector unsigned long long vconst2 = vec_ld(16, v_fold2_reflect_const);
    __vector unsigned long long vconst3 = vec_ld(32, v_fold2_reflect_const);

	__vector unsigned char vsht_splat;
	__vector unsigned long long vdata, v0, v1;

	unsigned long result = 0;

	vdata = vec_ld(0, (__vector unsigned long long*) data);
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
	__vector unsigned long long vconstp = vec_ld(48, v_fold2_reflect_const);
	vdata = vec_perm (vdata, vdata, (__vector unsigned char)vconstp);
#endif

	/*
	 * We append 32 bits of zeroes to our 128 bit value. This gives us 192
	 * bits that we reduce in two steps. This time we are reducing the
	 * bits on the right side (ie the lower bits) and xor'ing them
	 * on the left side.
	 */

	v0 = (__vector unsigned long long)__builtin_crypto_vpmsumw (
			(__vector unsigned int)vdata,(__vector unsigned int)vconst1);
	/* xor two 64 bit results together */
	v1 = (__vector unsigned long long)vec_sld ((__vector unsigned char)v0,
			(__vector unsigned char)v0, 8);
	v0 = vec_xor (v1, v0);

	/* shift left one bit */
	vsht_splat = vec_splat_u8 (1);
	v0 = (__vector unsigned long long)vec_sll ((__vector unsigned char)v0,
			vsht_splat);

	v0 = vec_and (v0, vmask_64bit);

	/*
	 * Now for Barrett reduction. The idea is to calculate q,
	 * the multiple of our polynomial that we need to subtract. By
	 * doing the computation 2x bits higher (ie 64 bits) and shifting the
	 * result back down 2x bits, we round down to the nearest multiple.
	 */
	/* bottom 32 bits of a */
	v1 = vec_and (v0, vmask_32bit);
	/* ma */
	v1 = __builtin_crypto_vpmsumd ((__vector unsigned long long)v1,
			(__vector unsigned long long)vconst2);
	/* bottom 32 bits of ma */
	v1 = vec_and (v1, vmask_32bit);
	/* qn */
	v1 = __builtin_crypto_vpmsumd ((__vector unsigned long long)v1,
			(__vector unsigned long long)vconst3);
	/* a - qn, subtraction is xor in GF(2) */
	v0 = vec_xor (v0, v1);
	/*
	 * Get the result into r3. We need to shift it left 8 bytes:
	 * V0 [ 0 1 2 X ]
	 * V0 [ 0 X 2 3 ]
	 */
	v0 = (__vector unsigned long long)vec_sld ((__vector unsigned char)v0,
			(__vector unsigned char)vzero, 4);
	result = __builtin_unpack_vector_int128 ((vector __int128_t)v0, 0);

	return result;
}
