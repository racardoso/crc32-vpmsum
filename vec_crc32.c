/*
* vec_crc32.c
* Author: rcardoso
*
*/

#include <stdio.h>
#include <altivec.h>
/*TODO: Maybe we should check if power8 instrisics are supported*/
#define __ASSEMBLY__
#define POWER8_INTRINSICS

#include "crc32_constants.h"

#if defined(__BIG_ENDIAN__) && defined (REFLECT)
#define BYTESWAP_DATA
#elif defined(__LITTLE_ENDIAN__) && !defined(REFLECT)
#define BYTESWAP_DATA
#endif


/*TODO: Check this constant */
/* On crc32.S I don't know why they need to permute this constant
   makes no sense to me since you can ifdef the constant on the right order
   instead generates a vperm
*/
#ifdef BYTESWAP_DATA


static const __vector unsigned long long vperm_const
    __attribute__ ((aligned(16))) = { 0x08090A0B0C0D0E0FUL,
            0x0001020304050607UL };

#else

/* byte reverse permute constant */
static const __vector unsigned long long vperm_const
	__attribute__ ((aligned(16))) = { 0X0706050403020100UL,
			0x0F0E0D0C0B0A0908UL };
#endif

unsigned int __attribute__ ((aligned (32)))
__crc32_vpmsum(unsigned int crc, void* p, unsigned long len)
{
	const __vector unsigned long long vzero = {0,0};
	const __vector unsigned long long vones = {0xffffffffffffffffUL,
		0xffffffffffffffffUL};

	const __vector unsigned long long vmask_32bit =
		(__vector unsigned long long)vec_sld((__vector unsigned char)vzero,
			(__vector unsigned char)vones, 4);

	const __vector unsigned long long vmask_64bit =
		(__vector unsigned long long)vec_sld((__vector unsigned char)vzero,
			(__vector unsigned char)vones, 8);

	__vector unsigned long long va, vcrc, v1;

	/* v0-v7 will contain our checksums */
	/* __vector unsigned long long v0, v1, v2, v3, v4, v5, v6, v7;*/
	unsigned int result = 0;

#ifdef REFLECT
	vcrc = (__vector unsigned long long)__builtin_pack_vector_int128(0UL, crc);
#else
	vcrc = (__vector unsigned long long)__builtin_pack_vector_int128(crc, 0UL);
	/* Shift into top 32 bits */
	vcrc = (__vector unsigned long long)vec_sld((__vector unsigned char)vcrc,
        (__vector unsigned char)vzero, 4);
#endif

	/*.Lshort*/
	/* TODO Need to improve */
	if (len < 256) {
		__vector unsigned long long vconst, vdata;
		unsigned long i;
		unsigned int offset = 256 - len;

		/*TODO Reorganize this loop to remove those multiply/divide operations*/
		/* Unrolling??? */
		/*__attribute__((optimize("unroll loops")))*/
		for (i = 0; i < len/16; i++){
			/* TODO: Better load the initial value outside the loop */
			vconst = vec_ld(offset + (i*16), v_crc_short_const);
			vdata = vec_ld((i*16), (__vector unsigned long long*) p);
			#ifdef BYTESWAP_DATA
			vdata = vec_perm(vdata, vconst, (__vector unsigned char) vperm_const);
			#endif
			/* TODO: very ugly.*/
			if (i == 0)
				vdata = vec_xor(vdata,vcrc);
			vdata = (__vector unsigned long long) __builtin_crypto_vpmsumw
				((__vector unsigned int)vdata, (__vector unsigned int)vconst);
			va = vec_xor(va, vdata);
		}
	}

	/* Barrett Reduction */
	__vector unsigned long long vbconst1 = vec_ld(0, v_barrett_const);
	__vector unsigned long long vbconst2 = vec_ld(16, v_barrett_const);

	v1 = (__vector unsigned long long)vec_sld((__vector unsigned char)va,(__vector unsigned char)va, 8);
	va = vec_xor(v1,va);
#ifdef REFLECT
/*TODO: vspltisb v1, 1
		vsl v0,v0,vq
*/

#endif
	va = vec_and(va,vmask_64bit);
#ifndef REFLECT

	/*
	 * Now for the actual algorithm. The idea is to calculate q,
	 * the multiple of our polynomial that we need to subtract. By
	 * doing the computation 2x bits higher (ie 64 bits) and shifting the
	 * result back down 2x bits, we round down to the nearest multiple.
	 */
	/* ma */
	v1 = __builtin_crypto_vpmsumd ((__vector unsigned long long)va,
			(__vector unsigned long long)vbconst1);
	/* q = floor(ma/(2^64)) */
	v1 = (__vector unsigned long long)vec_sld ((__vector unsigned char)vzero,
			(__vector unsigned char)v1, 8);
	/* qn */
	v1 = __builtin_crypto_vpmsumd ((__vector unsigned long long)v1,
			(__vector unsigned long long)vbconst2);
	/* a - qn, subtraction is xor in GF(2) */
	va = vec_xor (va, v1);
	/*
	 * Get the result into r3. We need to shift it left 8 bytes:
	 * V0 [ 0 1 2 X ]
	 * V0 [ 0 X 2 3 ]
	 */
#endif

	result = __builtin_unpack_vector_int128 ((vector __int128_t)va, 1);
	return result;
}
