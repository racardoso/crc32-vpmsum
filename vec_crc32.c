/*
* vec_crc32.c
* Author: rcardoso
* TODO: License
*/

#include <stdio.h>
#include <altivec.h>

/*TODO: Maybe we should check if power8 instrisics are supported. */
#define __ASSEMBLY__
#define POWER8_INTRINSICS

#include "crc32_constants.h"

#define VEC_DUMP(v)printf("0x%lx%lx\n", v[1], v[0]);

#if defined(__BIG_ENDIAN__) && defined (REFLECT)
#define BYTESWAP_DATA
#elif defined(__LITTLE_ENDIAN__) && !defined(REFLECT)
#define BYTESWAP_DATA
#endif

#ifdef BYTESWAP_DATA
#define VEC_PERM(vr, va, vb, vc) vr = vec_perm(va, vb,\
										(__vector unsigned char) vc)
/* Byte reverse permute constant LE. */
static const __vector unsigned long long vperm_const
    __attribute__ ((aligned(16))) = { 0x08090A0B0C0D0E0FUL,
            0x0001020304050607UL };
#else
#define VEC_PERM(va,vb,vc)
/* Byte reverse permute constant. */
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
	__vector unsigned long long vd8, vd1, vd2, vd3, vd4, vd5, vd6, vd7;
	unsigned int result = 0;

#ifdef REFLECT
	vcrc = (__vector unsigned long long)__builtin_pack_vector_int128(0UL, crc);
#else
	vcrc = (__vector unsigned long long)__builtin_pack_vector_int128(crc, 0UL);
	/* Shift into top 32 bits */
	vcrc = (__vector unsigned long long)vec_sld((__vector unsigned char)vcrc,
        (__vector unsigned char)vzero, 4);
#endif

	/* Short version. */
	if (len < 256) {
		__vector unsigned long long vconst, vdata;
		unsigned long i;
		/* Calculate where in the constant table we need to start. */
		unsigned int offset = 256 - len;

		va = vec_xor(va, va);

		vconst = vec_ld(offset, v_crc_short_const);
		vdata = vec_ld(0, (__vector unsigned long long*) p);
		VEC_PERM(vdata, vdata, vconst, vperm_const);

		/* xor initial value*/
		vdata = vec_xor(vdata, vcrc);

		vdata = (__vector unsigned long long) __builtin_crypto_vpmsumw
				((__vector unsigned int)vdata, (__vector unsigned int)vconst);
		va = vec_xor(va, vdata);

		for (i = 16; i < len; i += 16) {
			vconst = vec_ld(offset + i, v_crc_short_const);
			vdata = vec_ld(i, (__vector unsigned long long*) p);
			VEC_PERM(vdata, vdata, vconst, vperm_const);
			vdata = (__vector unsigned long long) __builtin_crypto_vpmsumw
				((__vector unsigned int)vdata, (__vector unsigned int)vconst);
			va = vec_xor(va, vdata);
		}
	} else {
		/*TODO Move all to the begin of file, */
		long i, chunks;
		int loopback = 0;

		/* Align by 128 bits. The last 128 bit block will be processed at end.
         */
		unsigned long length = len & 0xFFFFFFFFFFFFFF80UL;

		__vector unsigned long long vconst1,vconst2, vdata1, vdata2, vdata3,
			vdata4, vdata5, vdata6, vdata7, vdata8;

		__vector unsigned long long va1, va2, va3, va4, va5, va6, va7, va8;

		unsigned int offset;
		unsigned long block_size;

		do {
			/* Checksum in blocks of MAX_SIZE. */
			block_size = length;
			if (block_size > MAX_SIZE) {
				block_size = MAX_SIZE;
			}

			length = length - block_size;

			/* zero v0-v7 which will contain our checksums */
			vd1 = vec_xor(vd1, vd1);
			vd2 = vec_xor(vd2, vd2);
			vd3 = vec_xor(vd3, vd3);
			vd4 = vec_xor(vd4, vd4);
			vd5 = vec_xor(vd5, vd5);
			vd6 = vec_xor(vd6, vd6);
			vd7 = vec_xor(vd7, vd7);
			vd8 = vec_xor(vd8, vd8);

			/*
			* Work out the offset into the constants table to start at. Each
			* constant is 16 bytes, and it is used against 128 bytes of input
			* data - 128 / 16 = 8
			*/
			offset = (MAX_SIZE/8) - (block_size/8);
			/* We reduce our final 128 bytes in a separate step */
			chunks = (block_size/128)-1;

			/*
			 * If we are looping back to consume more data we use the values
			 * already in v16-v23.
			 */
			if (!loopback) {
				vdata1 = vec_ld(0, (__vector unsigned long long*) p);
				VEC_PERM(vdata1, vdata1, vdata1, vperm_const);

				/* xor in initial value */
				vdata1 = vec_xor(vdata1, vcrc);

				vdata2 = vec_ld(16, (__vector unsigned long long*) p);
				VEC_PERM(vdata2, vdata2, vdata2, vperm_const);

				vdata3 = vec_ld(32, (__vector unsigned long long*) p);
				VEC_PERM(vdata3, vdata3, vdata3, vperm_const);

				vdata4 = vec_ld(48, (__vector unsigned long long*) p);
				VEC_PERM(vdata4, vdata4, vdata4, vperm_const);

				vdata5 = vec_ld(64, (__vector unsigned long long*) p);
				VEC_PERM(vdata5, vdata5, vdata5, vperm_const);

				vdata6 = vec_ld(80, (__vector unsigned long long*) p);
				VEC_PERM(vdata6, vdata6, vdata6, vperm_const);

				vdata7 = vec_ld(96, (__vector unsigned long long*) p);
				VEC_PERM(vdata7, vdata7, vdata7, vperm_const);

				vdata8 = vec_ld(112, (__vector unsigned long long*) p);
				VEC_PERM(vdata8, vdata8, vdata8, vperm_const);

				vconst1 = vec_ld(offset, v_crc_const);
				p += 128;
			}

		    vconst1 = vec_ld(offset, v_crc_const);
			/* First warmup done */
			/* TODO Colapse this block with the block bellow and change
			 * 'else' to 'if chunks != 1' to simplify. */
			if (chunks == 1) {
				offset += 16;

				va1 = __builtin_crypto_vpmsumd ((__vector unsigned long long)
							vdata1, (__vector unsigned long long)vconst1);
				va2 = __builtin_crypto_vpmsumd ((__vector unsigned long long)
							vdata2, (__vector unsigned long long)vconst1);
				va3 = __builtin_crypto_vpmsumd ((__vector unsigned long long)
							vdata3, (__vector unsigned long long)vconst1);
				va4 = __builtin_crypto_vpmsumd ((__vector unsigned long long)
							vdata4, (__vector unsigned long long)vconst1);
				va5 = __builtin_crypto_vpmsumd ((__vector unsigned long long)
							vdata5, (__vector unsigned long long)vconst1);
				va6 = __builtin_crypto_vpmsumd ((__vector unsigned long long)
							vdata6, (__vector unsigned long long)vconst1);
				va7 = __builtin_crypto_vpmsumd ((__vector unsigned long long)
							vdata7, (__vector unsigned long long)vconst1);
				va8 = __builtin_crypto_vpmsumd ((__vector unsigned long long)
							vdata8, (__vector unsigned long long)vconst1);
			} else {
				/* Second warmup pass*/
				offset += 16;
				vconst2 = vec_ld(offset, v_crc_const);

				va1 = __builtin_crypto_vpmsumd ((__vector unsigned long long)
							vdata1, (__vector unsigned long long)vconst1);
				va2 = __builtin_crypto_vpmsumd ((__vector unsigned long long)
							vdata2, (__vector unsigned long long)vconst1);
				va3 = __builtin_crypto_vpmsumd ((__vector unsigned long long)
							vdata3, (__vector unsigned long long)vconst1);
				va4 = __builtin_crypto_vpmsumd ((__vector unsigned long long)
							vdata4, (__vector unsigned long long)vconst1);
				va5 = __builtin_crypto_vpmsumd ((__vector unsigned long long)
							vdata5, (__vector unsigned long long)vconst1);
				va6 = __builtin_crypto_vpmsumd ((__vector unsigned long long)
							vdata6, (__vector unsigned long long)vconst1);
				va7 = __builtin_crypto_vpmsumd ((__vector unsigned long long)
							vdata7, (__vector unsigned long long)vconst1);
				va8 = __builtin_crypto_vpmsumd ((__vector unsigned long long)
							vdata8, (__vector unsigned long long)vconst1);

				vdata1 = vec_ld(0, (__vector unsigned long long*) p);
				VEC_PERM(vdata1, vdata1, vdata1, vperm_const);

				vdata2 = vec_ld(16, (__vector unsigned long long*) p);
				VEC_PERM(vdata2, vdata2, vdata2, vperm_const);

				vdata3 = vec_ld(32, (__vector unsigned long long*) p);
				VEC_PERM(vdata3, vdata3, vdata3, vperm_const);

				vdata4 = vec_ld(48, (__vector unsigned long long*) p);
				VEC_PERM(vdata4, vdata4, vdata4, vperm_const);

				vdata5 = vec_ld(64, (__vector unsigned long long*) p);
				VEC_PERM(vdata5, vdata5, vdata5, vperm_const);

				vdata6 = vec_ld(80, (__vector unsigned long long*) p);
				VEC_PERM(vdata6, vdata6, vdata6, vperm_const);

				vdata7 = vec_ld(96, (__vector unsigned long long*) p);
				VEC_PERM(vdata7, vdata7, vdata7, vperm_const);

				vdata8 = vec_ld(112, (__vector unsigned long long*) p);
				VEC_PERM(vdata8, vdata8, vdata8, vperm_const);

				p += 128;

				/*
				 * main loop. We modulo schedule it such that it takes three
				 * iterations to complete - first iteration load, second
				 * iteration vpmsum, third iteration xor.
				 */
				for (i = 0; i < chunks-2; i++, p += 128) {
					vconst1 = vec_ld(offset, v_crc_const);
					offset += 16;

					vd1 = vec_xor(vd1, va1);
					va1 = __builtin_crypto_vpmsumd ((__vector unsigned long
							long)vdata1, (__vector unsigned long long)vconst2);
					vdata1 = vec_ld(0, (__vector unsigned long long*) p);
					VEC_PERM(vdata1, vdata1, vdata1, vperm_const);

					vd2 = vec_xor(vd2, va2);
					va2 = __builtin_crypto_vpmsumd ((__vector unsigned long
							long)vdata2, (__vector unsigned long long)vconst2);
					vdata2 = vec_ld(16, (__vector unsigned long long*) p);
					VEC_PERM(vdata2, vdata2, vdata2, vperm_const);

					vd3 = vec_xor(vd3, va3);
					va3 = __builtin_crypto_vpmsumd ((__vector unsigned long
							long)vdata3, (__vector unsigned long long)vconst2);
					vdata3 = vec_ld(32, (__vector unsigned long long*) p);
					VEC_PERM(vdata3, vdata3, vdata3, vperm_const);

					vd4 = vec_xor(vd4, va4);
					va4 = __builtin_crypto_vpmsumd ((__vector unsigned long
							long)vdata4, (__vector unsigned long long)vconst2);
					vdata4 = vec_ld(48, (__vector unsigned long long*) p);
					VEC_PERM(vdata4, vdata4, vdata4, vperm_const);

					vconst2 = vec_ld(offset, v_crc_const);

					vd5 = vec_xor(vd5, va5);
					va5 = __builtin_crypto_vpmsumd ((__vector unsigned long
							long)vdata5, (__vector unsigned long long)vconst1);
					vdata5 = vec_ld(64, (__vector unsigned long long*) p);
					VEC_PERM(vdata5, vdata5, vdata5, vperm_const);

					vd6 = vec_xor(vd6, va6);
					va6 = __builtin_crypto_vpmsumd ((__vector unsigned long
							long)vdata6, (__vector unsigned long long)vconst1);
					vdata6 = vec_ld(80, (__vector unsigned long long*) p);
					VEC_PERM(vdata6, vdata6, vdata6, vperm_const);

					vd7 = vec_xor(vd7, va7);
					va7 = __builtin_crypto_vpmsumd ((__vector unsigned long
							long)vdata7, (__vector unsigned long long)vconst1);
					vdata7 = vec_ld(96, (__vector unsigned long long*) p);
					VEC_PERM(vdata7, vdata7, vdata7, vperm_const);

					vd8 = vec_xor(vd8, va8);
					va8 = __builtin_crypto_vpmsumd ((__vector unsigned long
							long)vdata8, (__vector unsigned long long)vconst1);
					vdata8 = vec_ld(112, (__vector unsigned long long*) p);
					VEC_PERM(vdata8, vdata8, vdata8, vperm_const);
				}

				/* First cool down*/
				vconst1 = vec_ld(offset, v_crc_const);
				offset += 16;

				vd1 = vec_xor(vd1, va1);
				va1 = __builtin_crypto_vpmsumd ((__vector unsigned long long)
								vdata1, (__vector unsigned long long)vconst1);

				vd2 = vec_xor(vd2, va2);
				va2 = __builtin_crypto_vpmsumd ((__vector unsigned long long)
								vdata2, (__vector unsigned long long)vconst1);

				vd3 = vec_xor(vd3, va3);
				va3 = __builtin_crypto_vpmsumd ((__vector unsigned long long)
								vdata3, (__vector unsigned long long)vconst1);

				vd4 = vec_xor(vd4, va4);
				va4 = __builtin_crypto_vpmsumd ((__vector unsigned long long)
								vdata4, (__vector unsigned long long)vconst1);

				vd5 = vec_xor(vd5, va5);
				va5 = __builtin_crypto_vpmsumd ((__vector unsigned long long)
								vdata5, (__vector unsigned long long)vconst1);

				vd6 = vec_xor(vd6, va6);
				va6 = __builtin_crypto_vpmsumd ((__vector unsigned long long)
								vdata6, (__vector unsigned long long)vconst1);

				vd7 = vec_xor(vd7, va7);
				va7 = __builtin_crypto_vpmsumd ((__vector unsigned long long)
								vdata7, (__vector unsigned long long)vconst1);

				vd8 = vec_xor(vd8, va8);
				va8 = __builtin_crypto_vpmsumd ((__vector unsigned long long)
								vdata8, (__vector unsigned long long)vconst1);

			}

			/* Second cool down. */
			vd1 = vec_xor(vd1, va1);
			vd2 = vec_xor(vd2, va2);
			vd3 = vec_xor(vd3, va3);
			vd4 = vec_xor(vd4, va4);
			vd5 = vec_xor(vd5, va5);
			vd6 = vec_xor(vd6, va6);
			vd7 = vec_xor(vd7, va7);
			vd8 = vec_xor(vd8, va8);

#ifdef REFLECT
	/*TODO*/
#endif

			/* xor with the last 1024 bits. */
			va1 = vec_ld(0, (__vector unsigned long long*) p);
			VEC_PERM(va1, va1, va1, vperm_const);

			va2 = vec_ld(16, (__vector unsigned long long*) p);
			VEC_PERM(va2, va2, va2, vperm_const);

			va3 = vec_ld(32, (__vector unsigned long long*) p);
			VEC_PERM(va3, va3, va3, vperm_const);

			va4 = vec_ld(48, (__vector unsigned long long*) p);
			VEC_PERM(va4, va4, va4, vperm_const);

			va5 = vec_ld(64, (__vector unsigned long long*) p);
			VEC_PERM(va5, va5, va5, vperm_const);

			va6 = vec_ld(80, (__vector unsigned long long*) p);
			VEC_PERM(va6, va6, va6, vperm_const);

			va7 = vec_ld(96, (__vector unsigned long long*) p);
			VEC_PERM(va7, va7, va7, vperm_const);

			va8 = vec_ld(112, (__vector unsigned long long*) p);
			VEC_PERM(va8, va8, va8, vperm_const);

			p += 128;

			vdata1 = vec_xor(vd1, va1);
			vdata2 = vec_xor(vd2, va2);
			vdata3 = vec_xor(vd3, va3);
			vdata4 = vec_xor(vd4, va4);
			vdata5 = vec_xor(vd5, va5);
			vdata6 = vec_xor(vd6, va6);
			vdata7 = vec_xor(vd7, va7);
			vdata8 = vec_xor(vd8, va8);

			/* Check if we have more blocks to process */
			loopback = 0;
			if (length != 0) {
				loopback = 1;
			}
			length = length + 128;

		} while (loopback);

		/* Calculate how many bytes we have left. */
		length = (len & 127);

		/* Calculate where in (short) constant table we need to start. */
		offset = 128 - length;

		vd1 = vec_ld(offset, v_crc_short_const);
        vd2 = vec_ld(offset + 16, v_crc_short_const);
        vd3 = vec_ld(offset + 32, v_crc_short_const);
        vd4 = vec_ld(offset + 48, v_crc_short_const);
        vd5 = vec_ld(offset + 64, v_crc_short_const);
        vd6 = vec_ld(offset + 80, v_crc_short_const);
        vd7 = vec_ld(offset + 96, v_crc_short_const);
        vd8 = vec_ld(offset + 112, v_crc_short_const);

		offset += 128;

		vd1 = (__vector unsigned long long)__builtin_crypto_vpmsumw (
			(__vector unsigned int)vdata1,(__vector unsigned int)vd1);
		vd2 = (__vector unsigned long long)__builtin_crypto_vpmsumw (
			(__vector unsigned int)vdata2,(__vector unsigned int)vd2);
		vd3 = (__vector unsigned long long)__builtin_crypto_vpmsumw (
			(__vector unsigned int)vdata3,(__vector unsigned int)vd3);
		vd4 = (__vector unsigned long long)__builtin_crypto_vpmsumw (
			(__vector unsigned int)vdata4,(__vector unsigned int)vd4);
		vd5 = (__vector unsigned long long)__builtin_crypto_vpmsumw (
			(__vector unsigned int)vdata5,(__vector unsigned int)vd5);
		vd6 = (__vector unsigned long long)__builtin_crypto_vpmsumw (
			(__vector unsigned int)vdata6,(__vector unsigned int)vd6);
		vd7 = (__vector unsigned long long)__builtin_crypto_vpmsumw (
			(__vector unsigned int)vdata7,(__vector unsigned int)vd7);
		vd8 = (__vector unsigned long long)__builtin_crypto_vpmsumw (
			(__vector unsigned int)vdata8,(__vector unsigned int)vd8);

		/* Now reduce the tail (0-112 bytes). */
		for (i = 0; i < length; i+=16) {
			vdata1 = vec_ld(i,(__vector unsigned long long*)p);
			VEC_PERM(vdata1, vdata1, vdata1, vperm_const);
			va1 = vec_ld(offset + i,v_crc_short_const);
			va1 = (__vector unsigned long long)__builtin_crypto_vpmsumw (
			(__vector unsigned int)vdata1,(__vector unsigned int)va1);
			vd1 = vec_xor(vd1, va1);
		}

		/* xor all parallel chunks together. */
		vd1 = vec_xor(vd1, vd2);
		vd3 = vec_xor(vd3, vd4);
		vd5 = vec_xor(vd5, vd6);
		vd7 = vec_xor(vd7, vd8);

		vd1 = vec_xor(vd1, vd3);
		vd5 = vec_xor(vd5, vd7);

		va = vec_xor(vd1, vd5);
	}

	/* Barrett Reduction */
	__vector unsigned long long vbconst1 = vec_ld(0, v_barrett_const);
	__vector unsigned long long vbconst2 = vec_ld(16, v_barrett_const);

	v1 = (__vector unsigned long long)vec_sld((__vector unsigned char)va,
			(__vector unsigned char)va, 8);
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
