#include "aes_locl.h"
#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>

#define write_aes_register_bigendian(addr, variable)                           \
  asm volatile(".byte " #addr "\n"                                             \
               ".byte 0x81\n"                                                  \
               ".byte 0b10000000+(%0-0x100)\n"                                 \
               ".byte 0b01001000\n"                                            \
               :                                                               \
               : "r"(variable));

#define write_aes_register_bigendian4(addr, v0, v1, v2, v3)                    \
  asm volatile(".byte " #addr "\n"                                             \
               ".byte 0x81\n"                                                  \
               ".byte 0b10000000+(%0-0x100)\n"                                 \
               ".byte 0b01001000\n"                                            \
               ".byte " #addr"+1\n"                                            \
               ".byte 0x81\n"                                                  \
               ".byte 0b10000000+(%1-0x100)\n"                                 \
               ".byte 0b01001000\n"                                            \
               ".byte " #addr"+2\n"                                            \
               ".byte 0x81\n"                                                  \
               ".byte 0b10000000+(%2-0x100)\n"                                 \
               ".byte 0b01001000\n"                                            \
               ".byte " #addr"+3\n"                                            \
               ".byte 0x81\n"                                                  \
               ".byte 0b10000000+(%3-0x100)\n"                                 \
               ".byte 0b01001000\n"                                            \
               :                                                               \
               : "r"(v0), "r"(v1), "r"(v2), "r"(v3));

#define read_aes_register_bigendian(addr, variable)                            \
  asm volatile(".byte " #addr "\n"                                             \
               ".byte 0x81\n"                                                  \
               ".byte 0b00000000+(%0-0x100)\n"                                 \
               ".byte 0b01001000\n"                                            \
               : "=r"(variable));

#define write_aes_register(addr, variable)                                     \
  asm volatile(".byte " #addr "\n"                                             \
               ".byte 0x01\n"                                                  \
               ".byte 0b10000000+(%0-0x100)\n"                                 \
               ".byte 0b01001000\n"                                            \
               :                                                               \
               : "r"(variable));

#define read_aes_register(addr, variable)                                      \
  asm volatile(".byte " #addr "\n"                                             \
               ".byte 0x01\n"                                                  \
               ".byte 0b00000000+(%0-0x100)\n"                                 \
               ".byte 0b01001000\n"                                            \
               : "=r"(variable));

#define GETU32(p) (*((u32 *)(p)))
#define SETU32(p, v) (*((u32 *)(p))) = ((v))

// encrypt(type=1), decrypt(type=0)
int AES_set_key(const unsigned char *userKey, const int bits, int type) {
  if (bits != 128 && bits != 256) {
    return -1;
  }
  u32 k0 = GETU32(userKey);
  u32 k1 = GETU32(userKey + 4);
  u32 k2 = GETU32(userKey + 8);
  u32 k3 = GETU32(userKey + 12);
  write_aes_register_bigendian4(0x10, k0, k1, k2, k3);
  if (bits == 256) {
    u32 k4 = GETU32(userKey + 16);
    u32 k5 = GETU32(userKey + 20);
    u32 k6 = GETU32(userKey + 24);
    u32 k7 = GETU32(userKey + 28);
	write_aes_register_bigendian4(0x14, k4, k5, k6, k7);
  }
  u32 config = (bits == 128 ? 0 : 2) + type; // 128bit or 256bit, encrypt/decrypt
  write_aes_register(0x0a, config);
  u32 ctrl = 1; // init
  write_aes_register(0x08, ctrl);

  return 0;
}

int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key) {
  return AES_set_key(userKey, bits, 1);
}

int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key) {
  return AES_set_key(userKey, bits, 0);
}

void AES_encrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key) {
  u32 d0 = GETU32(in);
  u32 d1 = GETU32(in + 4);
  u32 d2 = GETU32(in + 8);
  u32 d3 = GETU32(in + 12);
  write_aes_register_bigendian4(0x20, d0, d1, d2, d3);

  u32 status = 0;
  // wait for ready
  read_aes_register(0x09, status);
  while (!(status & 1)) {
    read_aes_register(0x09, status);
  }

  u32 ctrl = 2; // next
  write_aes_register(0x08, ctrl);

  // wait for valid
  read_aes_register(0x09, status);
  while (!(status & 2)) {
    read_aes_register(0x09, status);
  }
  u32 r0 = 0;
  u32 r1 = 0;
  u32 r2 = 0;
  u32 r3 = 0;
  read_aes_register_bigendian(0x30, r0);
  read_aes_register_bigendian(0x31, r1);
  read_aes_register_bigendian(0x32, r2);
  read_aes_register_bigendian(0x33, r3);
  SETU32(out, r0);
  SETU32(out + 4, r1);
  SETU32(out + 8, r2);
  SETU32(out + 12, r3);
}

void AES_decrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key) {
  AES_encrypt(in, out, key);
}
