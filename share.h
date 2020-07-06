//File from https://github.com/coron/htable. Author JS Coron.

#ifndef __share_h__
#define __share_h__

#include "aes.h"

unsigned long xorshf96(void);
void init_randcount(void);
unsigned int get_randcount(void);

void refresh(byte a[],int n);
void share(byte x,byte a[],int n);
byte xorop(byte a[],int n);
byte decode(byte a[],int n);

#endif
