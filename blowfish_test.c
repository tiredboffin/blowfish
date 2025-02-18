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

int test_recover_key(BLOWFISH_CTX *ctx, char *testkey, int len, int verbose)
{
  uint8_t tmp[64];

  if (verbose)
    print_P("Original P table  => \n", ctx);
  Blowfish_Recover_P(ctx);
  if (verbose)
    print_P("Recovered P table =>\n", ctx);
  Blowfish_Recover_Key(ctx, tmp, sizeof(tmp));
  // print_P("Recovered key (machine endianess) =>\n", ctx);
  if (verbose)
    print_hex("Recovered Key =>\n", tmp, sizeof(tmp));
  if (memcmp(tmp, testkey, len) == 0)
  {
    if (verbose)
      printf("Test key recovered OK\n");
    return 0;
  }
  else
  {
    if (verbose)
      printf("Test key recovery FAILED\n");
    return -1;
  }
}

#define NUM_RAND_TESTS (1 << 18)

int test_recover(BLOWFISH_CTX *ctx)
{

  P18 P;

  /* test N key */
  unsigned char nkey[] = {0xff, 0xff, 0xaa, 0x55, 0x11, 0x22, 0x33, 0x00};
  Blowfish_Init_P_from_Key(ctx, (uint8_t *)&nkey[0], sizeof(nkey));
  memcpy(P, ctx->P, sizeof(P));

  /* Pretend P is from external source otherwise this memcpy and Init_P_from_P()
     is not needed of course */
  Blowfish_Init_P_from_P(ctx, P);
  test_recover_key(ctx, nkey, sizeof(nkey), 1);

  /* test some randomly generated keys */
  srand(0x243F6A88L);
  printf("random key tests: %d rounds\n", NUM_RAND_TESTS);
  for (int k = 0; k < NUM_RAND_TESTS; k++)
  {
    uint32_t random_key[16];
    for (int i = 0; i < 16; i++)
    {
      random_key[i] = rand() % 0xFFFFFFFF;
    }
    Blowfish_Init_P_from_Key(ctx, (uint8_t *)random_key, sizeof(random_key));
    /* Not needed for testing
    memcpy(P, ctx->P, sizeof(P));
    Blowfish_Init_P_from_P(ctx, P);
    */
    if (test_recover_key(ctx, (uint8_t *)random_key, sizeof(random_key), 0) != 0)
    {
      print_hex("KEY:", (uint8_t *)random_key, sizeof(random_key));
      printf("random key test failed at %d round\n", k);
      return -1;
    }
  }
  printf("random key test OK\n");
  return 0;
}

int main(void)
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

  return test_recover(&ctx);
}
