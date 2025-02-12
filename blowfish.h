/*
blowfish.h:  Header file for blowfish.c

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


See blowfish.c for more information about this file.
*/

#include <inttypes.h>


typedef uint32_t P18[16 + 2];

typedef struct
{
  P18 P;
  uint32_t S[4][256];
} BLOWFISH_CTX;


typedef uint32_t P18[16 + 2];


void Blowfish_Init(BLOWFISH_CTX *ctx, uint8_t *key, int32_t keyLen);
void Blowfish_Encrypt(BLOWFISH_CTX *ctx, uint32_t *xl, uint32_t *xr);
void Blowfish_Decrypt(BLOWFISH_CTX *ctx, uint32_t *xl, uint32_t *xr);
void Blowfish_Init_P_from_P(BLOWFISH_CTX *ctx, P18 P);
void Blowfish_Init_P_from_Key(BLOWFISH_CTX *ctx, uint8_t *key, int32_t keyLen);
void Blowfish_Init_S(BLOWFISH_CTX *ctx);
void Blowfish_Recover_Key(BLOWFISH_CTX *ctx, uint8_t *keybuf, int keybufLen);
void Blowfish_Recover_P(BLOWFISH_CTX *ctx);
