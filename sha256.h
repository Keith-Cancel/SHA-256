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
#ifndef SHA_256_H
#define SHA_256_H

#include <stdint.h>


/**
* This function calculates the SHA-256 hash of the provided byte array.
*
* @param data     A pointer to the array to calculate from.
* @param len      The length of the data array.
* @param hash     A pointer to a buffer to store the resulting has.
* @param hash_len The length of output buffer. If less 32 bytes the hash will
*                 obviously be truncated to the length.
* @return No return value.
*/
void sha256(
    const uint8_t* data, size_t len,
    uint8_t* hash, size_t hash_len
);


/**
* This function calculates the SHA-256 HMAC from the byte array and key.
*
* @param data     A pointer to the array to calculate from.
* @param data_len The length of the data array.
* @param key      A pointer to the key array.
* @param key_len  The length of the key array.
* @param hash     A pointer to a buffer to store the resulting has.
* @param hash_len The length of output buffer. If less 32 bytes the hash will
*                 obviously be truncated to the length.
* @return No return value.
*/
void sha256_hmac(
    const uint8_t* key,  size_t key_len,
    const uint8_t* data, size_t data_len,
          uint8_t* hash, size_t hash_len
);

#endif