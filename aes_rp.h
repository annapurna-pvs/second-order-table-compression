//File from https://github.com/coron/htable. Author JS Coron.

#include "aes.h"

byte multtable(byte x,byte y);
void aes_rp(byte in[16],byte out[16],byte key[16]);
void subbyte_rp_share(byte *a,int n);
void multshare(byte *a,byte *b,byte *c,int n);
void subbyte_rp_share_func(byte *a,int n,void (*multshare_call)(byte *,byte *,byte *,int));
