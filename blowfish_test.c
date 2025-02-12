/*
blowfish_test.c:  Test file for blowfish.c

Copyright (C) 1997 by Paul Kocher
Copyright (C) 2025 by tiredboffin@gmail.com : add illustrative functions to demonstrate key recovery from a known pre-computed P-table.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.
This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.
You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "blowfish.h"

void print_hex(const char *msg, uint8_t *buf, int len)
{
  printf(msg);
  for (int i = 0; i < len; i++)
  {
    printf("%02x ", buf[i]);
  }
  printf("\n");
}

void print_P(const char *msg, BLOWFISH_CTX *ctx)
{
  printf(msg);
  for (int i = 0; i < 16; i++)
  {
    printf("%08lx ", ctx->P[i]);
  }
  printf("\n");
}

void test_recover_key(BLOWFISH_CTX *ctx, char *testkey, int len)
{
  uint8_t tmp[64];
  print_P("Original P table  => \n", ctx);
  Blowfish_Recover_P(ctx);
  print_P("Recovered P table =>\n", ctx);
  Blowfish_Recover_Key(ctx, tmp, sizeof(tmp));
  // print_P("Recovered key (machine endianess) =>\n", ctx);
  print_hex("Recovered Key =>\n", tmp, sizeof(tmp));
  if (memcmp(tmp, testkey, len) == 0)
    printf("Test key recovered OK\n");
  else
    printf("Test key recovery FAILED\n");
}

void test_recover(BLOWFISH_CTX *ctx)
{
  /* test N key */
  unsigned char nkey[] = {0xff, 0xff, 0xaa, 0x55, 0x11, 0x22, 0x33, 0x00};
  Blowfish_Init_P(ctx, (uint8_t *)&nkey[0], sizeof(nkey));
  test_recover_key(ctx, nkey, sizeof(nkey));

  /* test some randomly generated keys */
  for (int k = 0; k < 8; k++)
  {
    uint32_t random[16];
    for (int i = 0; i < 16; i++)
    {
      random[i] = rand() % 0xFFFFFFFF;
    }
    Blowfish_Init_P(ctx, (uint8_t *)&random[0], sizeof(random));
    test_recover_key(ctx, (uint8_t *)&random, sizeof(random));
  }
}

void main(void)
{
  uint32_t L = 1, R = 2;
  BLOWFISH_CTX ctx;

  Blowfish_Init(&ctx, (uint8_t *)"TESTKEY", 7);
  Blowfish_Encrypt(&ctx, &L, &R);
  printf("%08lX %08lX\n", (long unsigned int)L, (long unsigned int)R);
  if (L == 0xDF333FD2L && R == 0x30A71BB4L)
    printf("Test encryption OK.\n");
  else
    printf("Test encryption failed.\n");
  Blowfish_Decrypt(&ctx, &L, &R);
  if (L == 1 && R == 2)
    printf("Test decryption OK.\n");
  else
    printf("Test decryption failed.\n");

  test_recover(&ctx);
}
