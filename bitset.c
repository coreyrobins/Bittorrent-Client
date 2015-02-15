/*
 * Bit set data structure
 * Copyright (c) 2003, Jeffrey K. Hollingsworth <hollings@cs.umd.edu>
 * Copyright (c) 2003,2004 David Hovemeyer <daveho@cs.umd.edu>
 * $Revision: 1.2 $
 * 
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "COPYING".
 */

#include <stdlib.h>
#include <string.h>
#include "bitset.h"

#define FIND_OFFSET_AND_BIT(bitPos,offset,bit)  \
do {                        \
    offset = bitPos / 8;            \
    bit = 7 - (bitPos % 8);         \
} while (0)

#define FIND_NUM_BYTES(totalBits) \
    ((totalBits / 8) + ((totalBits % 8 != 0) ? 1 : 0))

void *Create_Bit_Set(uint_t totalBits) {
    ulong_t numBytes;
    void *bitSet;

    numBytes = FIND_NUM_BYTES(totalBits);

    bitSet = malloc(numBytes);
    if (bitSet != 0)
        memset(bitSet, '\0', numBytes);

    return bitSet;
}

void Set_Bit(void *bitSet, uint_t bitPos) {
    ulong_t offset, bit;

    FIND_OFFSET_AND_BIT(bitPos, offset, bit);
    ((unsigned char *) bitSet)[offset] |= (1 << bit);
}

void Clear_Bit(void *bitSet, uint_t bitPos) {
    ulong_t offset, bit;

    FIND_OFFSET_AND_BIT(bitPos, offset, bit);
    ((unsigned char *) bitSet)[offset] &= ~(1 << bit);
}

bool Is_Bit_Set(void *bitSet, uint_t bitPos) {
    ulong_t offset, bit;

    FIND_OFFSET_AND_BIT(bitPos, offset, bit);
    return (((unsigned char *) bitSet)[offset] & (1 << bit)) != 0;
}

int Find_First_Free_Bit(void *bitSet, ulong_t totalBits) {
    uint_t numBytes = FIND_NUM_BYTES(totalBits);
    ulong_t offset;
    unsigned char *bits = (unsigned char *) bitSet;

    for (offset = 0; offset < numBytes; ++offset) {
        if (bits[offset] != 0xff) {
            uint_t bit;
            for (bit = 0; bit < 8; ++bit) {
              if ((bits[offset] & (1 << (7-bit))) == 0)
                    return (offset * 8) + bit;
            }
        }
    }

    return -1;
}

/*
 * This is slow!!
 */
int Find_First_N_Free(void *bitSet, uint_t runLength, ulong_t totalBits) {
    uint_t i, j;

    for (i = 0; i < totalBits - runLength; i++) {
        if (!Is_Bit_Set(bitSet, i)) {
            for (j = 1; j < runLength; j++) {
                if (Is_Bit_Set(bitSet, i + j)) {
                    break;
                }
            }
            if (j == runLength) {
                return i;
            }
        }
    }
    return -1;
}

void Destroy_Bit_Set(void *bitSet) {
    free(bitSet);
}

#include <stdio.h>
void Print_Bit_Set(const void *bitSet, ulong_t totalBits) {
  int i;
  for(i=0; i<((totalBits+7) / 8); i++) {
    printf("%02x", ((unsigned char *)bitSet)[i]);
  }
  //   fprintf(stderr, "%lu tbits %d bytes\n", totalBits, i);
}

#ifdef STANDALONE_TEST
#include <assert.h>
int main() {
  void *bitset = Create_Bit_Set(100);
  assert(Find_First_Free_Bit(bitset,100) == 0);
  Set_Bit(bitset, 0);
  assert(Find_First_Free_Bit(bitset,100) == 1);
  Set_Bit(bitset, 1);
  assert(Find_First_Free_Bit(bitset,100) == 2);
  Set_Bit(bitset, 3);
  assert(Find_First_Free_Bit(bitset,100) == 2);
  Set_Bit(bitset, 4);
  Set_Bit(bitset, 5);
  Set_Bit(bitset, 6);
  Set_Bit(bitset, 7);
  assert(Find_First_Free_Bit(bitset,100) == 2);
  Set_Bit(bitset, 2);
  assert(Find_First_Free_Bit(bitset,100) == 8);
  Clear_Bit(bitset, 2);
  assert(Find_First_Free_Bit(bitset,100) == 2);
}
#endif