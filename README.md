# SHA-256 and HMAC SHA-256
 A simple C impletation of SHA-256 and SHA-256 HMAC.

## Usage Example (C)
A simple example that outputs some common test vectors.
```c

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sha256.h"

void print_long_hex_str(uint8_t* bytes, size_t len) {
    for(size_t i = 0; i < len; i++) {
        if(i > 0 && (i % 4) == 0) {
            printf(" ");
        }
        printf("%x%x", bytes[i] >> 4, bytes[i] & 0xf);
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    uint8_t hash[32];

    printf("SHA-256 of \"\"\n");
    sha256("", 0, hash, 32);
    print_long_hex_str(hash, 32);

    printf("\nSHA-256 of \"abc\"\n");
    sha256("abc", 3, hash, 32);
    print_long_hex_str(hash, 32);

    printf("\nSHA-256 of \"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\"\n");
    sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, hash, 32);
    print_long_hex_str(hash, 32);

    // SHA-256 of a million a's.
    uint8_t* mill_a = malloc(1000000);
    if(mill_a == NULL) {
        printf("Sadly, malloc has failed.\n");
        return 0;
    }
    memset(mill_a, 'a', 1000000);
    sha256(mill_a, 1000000, hash, 32);
    printf("\nSHA-256 of \"a\" repeated one million times\n");
    print_long_hex_str(hash, 32);
    free(mill_a);

    sha256_hmac(
        "key", 3,
        "The quick brown fox jumps over the lazy dog", 43,
        hash, 32
    );
    printf("\nHMAC SHA-256 of \"The quick brown fox jumps over the lazy dog\"\n");
    printf("Using key: \"key\"\n");
    print_long_hex_str(hash, 32);

    // From https://tools.ietf.org/html/rfc4231
    uint8_t key[] = {
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
    };
    sha256_hmac(
        key, sizeof(key),
        "Test Using Larger Than Block-Size Key - Hash Key First", 54,
        hash, 32
    );
    printf("\nHMAC SHA-256 of \"Test Using Larger Than Block-Size Key - Hash Key First\"\n");
    printf("Key is 131 bytes of 0xaa\n");
    print_long_hex_str(hash, 32);
    return 0;
}
```
## Example Output
Output from the simple example.

```
SHA-256 of ""
e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855

SHA-256 of "abc"
ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad

SHA-256 of "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1

SHA-256 of "a" repeated one million times
cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0

HMAC SHA-256 of "The quick brown fox jumps over the lazy dog"
Using key: "key"
f7bc83f4 30538424 b13298e6 aa6fb143 ef4d59a1 49461759 97479dbc 2d1a3cd8

HMAC SHA-256 of "Test Using Larger Than Block-Size Key - Hash Key First"
Key is 131 bytes of 0xaa
60e43159 1ee0b67f 0d8a26aa cbf5b77f 8e0bc621 3728c514 0546040f 0ee37f54
```