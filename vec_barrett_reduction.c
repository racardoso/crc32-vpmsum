/*
 * vec_barrett_reduction.c
 * Author: sjmunroe
 * Author: rcardoso
 * Created on:  May 11, 2017
 */

#include <stdint.h>
#include <altivec.h>

static const __vector unsigned long long v_Barrett_const[2]
	__attribute__ ((aligned (16))) = {
		/* Barrett constant m - (4^32)/n */
		{ 0x0000000104d101dfUL, 0x0000000000000000UL },
		/* Barrett constant n */
		{ 0x0000000104c11db7UL, 0x0000000000000000UL }
	};

static const __vector unsigned long long v_Barrett_reflect_const[2]
	__attribute__ ((aligned (16))) = {
		/* Barrett constant m - (4^32)/n */
		{ 0x00000001f7011641UL, 0x0000000000000000UL },
		/* Barrett constant n */
		{ 0x00000001db710641UL, 0x0000000000000000UL }
	};

unsigned long /*__attribute__ ((aligned (32)))*/
barrett_reduction (unsigned long data){
	const __vector unsigned long long vzero = {0,0};
	__vector unsigned long long vconst1 = vec_ld(0, v_Barrett_const);
	__vector unsigned long long vconst2 = vec_ld(16, v_Barrett_const);

	__vector unsigned long long  va, v0, v4;

	unsigned long result = 0;
	/* Get (unsigned long) a into v0 */
	va = (__vector unsigned long long)__builtin_pack_vector_int128(0UL, data);

	/*
	 * Now for the actual algorithm. The idea is to calculate q,
	 * the multiple of our polynomial that we need to subtract. By
	 * doing the computation 2x bits higher (ie 64 bits) and shifting the
	 * result back down 2x bits, we round down to the nearest multiple.
	 */
	/* ma */
	v4 = __builtin_crypto_vpmsumd ((__vector unsigned long long)va,
			(__vector unsigned long long)vconst1);
	/* q = floor(ma/(2^64)) */
	v4 = (__vector unsigned long long)vec_sld ((__vector unsigned char)vzero,
			(__vector unsigned char)v4, 8);
	/* qn */
	v4 = __builtin_crypto_vpmsumd ((__vector unsigned long long)v4,
			(__vector unsigned long long)vconst2);
	/* a - qn, subtraction is xor in GF(2) */
	v0 = vec_xor (va, v4);
	/*
	 * Get the result into r3. We need to shift it left 8 bytes:
	 * V0 [ 0 1 2 X ]
	 * V0 [ 0 X 2 3 ]
	 */

	result = __builtin_unpack_vector_int128 ((vector __int128_t)v0, 1);

	return result;
}

unsigned long __attribute__ ((aligned (32)))
barrett_reduction_reflected (unsigned long data){
	const __vector unsigned long long vzero = {0,0};
	const __vector unsigned long long vones = {0xffffffffffffffffUL,
												0xffffffffffffffffUL};
	const __vector unsigned long long vmask_32bit =
		(__vector unsigned long long)vec_sld((__vector unsigned char)vzero,
			(__vector unsigned char)vones, 4);

	__vector unsigned long long vconst1 = vec_ld(0, v_Barrett_reflect_const);
	__vector unsigned long long vconst2 = vec_ld(16, v_Barrett_reflect_const);

	__vector unsigned long long va, v0, v4;
	unsigned long result = 0;
	/* Get (unsigned long) a into v0 */
	va = (__vector unsigned long long)__builtin_pack_vector_int128(0UL, data);
	/* shift into bottom 64 bits, this is a */
	v4 = (__vector unsigned long long)vec_sld ((__vector unsigned char)vzero,
			 (__vector unsigned char)va, 8);
	/*
	 * Now for the actual algorithm. The idea is to calculate q,
	 * the multiple of our polynomial that we need to subtract. By
	 * doing the computation 2x bits higher (ie 64 bits) and shifting the
	 * result back down 2x bits, we round down to the nearest multiple.
	 */
	/* bottom 32 bits of a */
	v4 = vec_and (va, vmask_32bit);
	/* ma */
	v4 = __builtin_crypto_vpmsumd ((__vector unsigned long long)v4,
			(__vector unsigned long long)vconst1);
	/* bottom 32 bits of a */
	v4 = vec_and (v4, vmask_32bit);
	/* qn */
	v4 = __builtin_crypto_vpmsumd ((__vector unsigned long long)v4,
			(__vector unsigned long long)vconst2);
	/* a - qn, subtraction is xor in GF(2) */
	v0 = vec_xor (va, v4);
	/*
		 * Since we are bit reflected, the result (ie the low 32 bits) is in the
		 * high 32 bits. We just need to shift it left 4 bytes
		 * V0 [ 0 1 X 3 ]
		 * V0 [ 0 X 2 3 ]
		 */
	v0 = (__vector unsigned long long)vec_sld((__vector unsigned char)v0,
			(__vector unsigned char)vzero, 4);
	result = __builtin_unpack_vector_int128 ((vector __int128_t)v0, 0);

	return result;
}
