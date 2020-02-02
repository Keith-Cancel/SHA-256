/*
MIT License
Copyright (c) 2020 Keith J. Cancel
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <string.h>
#include <stdbool.h>
#include "sha256.h"

#define ROTL32(x, a)   (((x) << (a)) | ((x) >> (32 - (a))))
#define ROTR32(x, a)   (((x) >> (a)) | ((x) << (32 - (a))))

#define ROTL64(x, a)   (((x) << (a)) | ((x) >> (64 - (a))))
#define ROTR64(x, a)   (((x) >> (a)) | ((x) << (64 - (a))))

#define FULL_GCC_VERSION (__GNUC__ * 100 + __GNUC_MINOR__)
// Clang builtin check
#ifndef __has_builtin
#  define __has_builtin(x) 0
#endif

#if FULL_GCC_VERSION > 402 || __has_builtin(__builtin_bswap32)
#define byte_swap32 __builtin_bswap32
#define byte_swap64 __builtin_bswap64
#else
static uint32_t byte_swap32(uint32_t value) {
    return (ROTR32(value, 8) & 0xff00ff00) |
           (ROTL32(value, 8) & 0x00ff00ff);
}
static uint64_t byte_swap64(uint64_t value) {
    return (ROTR64(value,  8) & 0xff000000ff000000) |
           (ROTL64(value,  8) & 0x000000ff000000ff) |
           (ROTR64(value, 24) & 0x00ff000000ff0000) |
           (ROTL64(value, 24) & 0x0000ff000000ff00);
}
#endif

#define CH(x, y, z)    (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z)   (((x) & (y)) ^ ( (x) & (z)) ^ ((y) & (z)))
#define SIGMA_0(x)     (ROTR32(x,  7) ^ ROTR32(x, 18) ^ (x >> 3))
#define SIGMA_1(x)     (ROTR32(x, 17) ^ ROTR32(x, 19) ^ (x >> 10))
#define CAP_SIGMA_0(x) (ROTR32(x,  2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define CAP_SIGMA_1(x) (ROTR32(x,  6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))

static inline bool is_litte_endian(void) {
    union {
        uint32_t v;
        uint8_t  b[4];
    } chk = {0x01000000};
    return chk.b[0] != 1;
}

static const uint32_t k[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

typedef enum {
    A = 0, B, C, D, E, F, G, H
} hIndexs;

// sched is 64 words and and st is the current hash state
static inline void calc_chunk(uint32_t* sched, uint32_t* st) {
    uint32_t S[8];
    memcpy(S, st, 8 * 4);
    for(int i = 0; i < 16 && is_litte_endian(); i++) {
        sched[i] = byte_swap32(sched[i]);
    }
    // Prep message schedule
    for(int t = 16; t < 64; t++) {
        sched[t]  = sched[t - 16];
        sched[t] += sched[t -  7];
        sched[t] += SIGMA_0(sched[t - 15]);
        sched[t] += SIGMA_1(sched[t -  2]);
    }
    for(int t = 0; t < 64; t++) {
        uint32_t T1, T2;
        T1  = S[H];
        T1 += CAP_SIGMA_1(S[E]);
        T1 += CH(S[E], S[F], S[G]);
        T1 += k[t];
        T1 += sched[t];

        T2  = CAP_SIGMA_0(S[A]);
        T2 += MAJ(S[A], S[B], S[C]);

        memmove(&S[1], S, 4 * 7);
        S[E] += T1; // D is already at E
        S[A]  = T1 + T2;
    }
    for(int i = 0; i < 8; i++) {
        st[i] += S[i];
    }
}

static void sha256_custom_init(const uint8_t* data, size_t len, uint32_t* init, size_t bytes_processed) {
    uint32_t chunk[64] = { 0 }; // extra 48 words for calc_chunk
    uint64_t bit_len   = (len + bytes_processed) * 8 ;
    bit_len = is_litte_endian() ? byte_swap64(bit_len) : bit_len;

    size_t remains = len;
    size_t chunks  =  (len + 9) >> 6;
    chunks        += ((len + 9) & 0x3f) > 0;

    for(size_t i = 0; i < chunks; i++) {
        size_t off = (i * sizeof(uint32_t) * 16);
        size_t amt = remains < 64 ? remains : 64;
        memcpy(chunk, data + off, amt);
        memset((uint8_t*)chunk + amt, 0, 64 - amt);
        if((amt + off) == len) {
            ((uint8_t*)chunk)[amt] |= 0x80;
        }
        if(i == (chunks - 1)) {
            memcpy(&chunk[14], &bit_len, 8);
        }
        calc_chunk(chunk, init);
        remains -= amt;
    }
}

void sha256(const uint8_t* data, size_t data_len, uint8_t* hash, size_t hash_len) {
    uint32_t init[] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    sha256_custom_init(data, data_len, init, 0);
    for(int i = 0; i < 8 && is_litte_endian(); i++) {
        init[i] = byte_swap32(init[i]);
    }
    memcpy(hash, init, 32);
}

#define IPAD   0x36363636
#define OPAD   0x5C5C5C5C
#define BLK_SZ 64

void sha256_hmac(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t* hash, size_t hash_len) {
    uint32_t i_key[64] = { 0 };
    uint32_t o_key[24] = {
        [0] = 0,
        [16] = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
               0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    if(key_len > BLK_SZ) {
        sha256(key, key_len, (uint8_t*)i_key, 32);
        key_len = 32;
    } else {
        memcpy(i_key, key, key_len);
    }
    memcpy(o_key, i_key, key_len);
    for(int i = 0; i < 16; i++) {
        i_key[i] ^= IPAD;
        o_key[i] ^= OPAD;
    }
    calc_chunk(i_key, &o_key[16]);
    sha256_custom_init(data, len, &o_key[16], 64);
    // swap for final hash for little endian
    for(int i = 0; i < 8 && is_litte_endian(); i++) {
        o_key[16 + i] = byte_swap32(o_key[16 + i]);
    }
    sha256((uint8_t*)o_key, 24 * 4, hash, hash_len);
}