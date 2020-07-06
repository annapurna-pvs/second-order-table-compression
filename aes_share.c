//File from https://github.com/coron/htable. Author JS Coron.

#include "aes_share.h"
#include "share.h"
#include "aes.h"

#include <stdlib.h>


void shiftrows_share(byte *stateshare[16],int n)
{
  byte m;
  int i;
  for(i=0;i<n;i++)
  {
    m=stateshare[1][i];
    stateshare[1][i]=stateshare[5][i];
    stateshare[5][i]=stateshare[9][i];
    stateshare[9][i]=stateshare[13][i];
    stateshare[13][i]=m;

    m=stateshare[2][i];
    stateshare[2][i]=stateshare[10][i];
    stateshare[10][i]=m;
    m=stateshare[6][i];
    stateshare[6][i]=stateshare[14][i];
    stateshare[14][i]=m;

    m=stateshare[3][i];
    stateshare[3][i]=stateshare[15][i];
    stateshare[15][i]=stateshare[11][i];
    stateshare[11][i]=stateshare[7][i];
    stateshare[7][i]=m;
  }
}

void mixcolumns_share(byte *stateshare[16],int n)
{
  byte ns[16];
  int i,j;
  for(i=0;i<n;i++)
  {
    for(j=0;j<4;j++)
    {
      ns[j*4]=multx(stateshare[j*4][i]) ^ multx(stateshare[j*4+1][i]) ^ stateshare[j*4+1][i] ^ stateshare[j*4+2][i] ^ stateshare[j*4+3][i];
      ns[j*4+1]=stateshare[j*4][i] ^ multx(stateshare[j*4+1][i]) ^ multx(stateshare[j*4+2][i]) ^ stateshare[j*4+2][i] ^ stateshare[j*4+3][i];
      ns[j*4+2]=stateshare[j*4][i] ^ stateshare[j*4+1][i] ^ multx(stateshare[j*4+2][i]) ^ multx(stateshare[j*4+3][i]) ^ stateshare[j*4+3][i];
      ns[j*4+3]=multx(stateshare[j*4][i]) ^ stateshare[j*4][i] ^ stateshare[j*4+1][i] ^ stateshare[j*4+2][i] ^ multx(stateshare[j*4+3][i]) ;
    }
    for(j=0;j<16;j++)
      stateshare[j][i]=ns[j];
  }
}


void shiftrows_share1(byte stateshare[16][3],int n)
{
  byte m;
  int i;
  for(i=0;i<n;i++)
  {
    m=stateshare[1][i];
    stateshare[1][i]=stateshare[5][i];
    stateshare[5][i]=stateshare[9][i];
    stateshare[9][i]=stateshare[13][i];
    stateshare[13][i]=m;

    m=stateshare[2][i];
    stateshare[2][i]=stateshare[10][i];
    stateshare[10][i]=m;
    m=stateshare[6][i];
    stateshare[6][i]=stateshare[14][i];
    stateshare[14][i]=m;

    m=stateshare[3][i];
    stateshare[3][i]=stateshare[15][i];
    stateshare[15][i]=stateshare[11][i];
    stateshare[11][i]=stateshare[7][i];
    stateshare[7][i]=m;
  }
}

void mixcolumns_share1(byte stateshare[16][3],int n)
{
  byte ns[16];
  int i,j;
  for(i=0;i<n;i++)
  {
    for(j=0;j<4;j++)
    {
      ns[j*4]=multx(stateshare[j*4][i]) ^ multx(stateshare[j*4+1][i]) ^ stateshare[j*4+1][i] ^ stateshare[j*4+2][i] ^ stateshare[j*4+3][i];
      ns[j*4+1]=stateshare[j*4][i] ^ multx(stateshare[j*4+1][i]) ^ multx(stateshare[j*4+2][i]) ^ stateshare[j*4+2][i] ^ stateshare[j*4+3][i];
      ns[j*4+2]=stateshare[j*4][i] ^ stateshare[j*4+1][i] ^ multx(stateshare[j*4+2][i]) ^ multx(stateshare[j*4+3][i]) ^ stateshare[j*4+3][i];
      ns[j*4+3]=multx(stateshare[j*4][i]) ^ stateshare[j*4][i] ^ stateshare[j*4+1][i] ^ stateshare[j*4+2][i] ^ multx(stateshare[j*4+3][i]) ;
    }
    for(j=0;j<16;j++)
      stateshare[j][i]=ns[j];
  }
}





void addroundkey_share(byte *stateshare[16],byte *wshare[176],int round,int n)
{
  int i,j;
  for(i=0;i<16;i++)
    for(j=0;j<n;j++)
      stateshare[i][j]^=wshare[16*round+i][j];
}


void addroundkey_share1(byte stateshare[16][3],byte wshare[176][3],int round,int n)
{
  int i,j;
  for(i=0;i<16;i++)
    for(j=0;j<n;j++)
      stateshare[i][j]^=wshare[16*round+i][j];
}



void subbytestate_share_compress(byte *stateshare[16],int n,int l,byte *t1,byte *r,byte* y1,void (*subbyte_share_call_compress)(byte *,byte,byte,byte *,byte *,byte*))
{
  int i;
  for(i=0;i<16;i++)
    subbyte_share_call_compress(stateshare[i],l,n,t1,r,y1);
}

// AES with shares. The subbyte computation with shares is given as parameter
void aes_share_subkeys_compress(byte in[16],byte out[16],byte *wshare[176],int n,int l,byte* t1,byte* r,byte* y1,void (*subbyte_share_call_compress)(byte *,byte,byte,byte *,byte *,byte*))
	{
  int i;
  int round=0;

  byte *stateshare[16];

  for(i=0;i<16;i++)
  {
    stateshare[i]=(byte*) malloc(n*sizeof(byte));
    share(in[i],stateshare[i],n);
    refresh(stateshare[i],n);
  }

  addroundkey_share(stateshare,wshare,0,n);

  for(round=1;round<10;round++)
  {
    subbytestate_share_compress(stateshare,n,l,t1,r,y1,subbyte_share_call_compress);
    shiftrows_share(stateshare,n);
    mixcolumns_share(stateshare,n);
    addroundkey_share(stateshare,wshare,round,n);
  }

  subbytestate_share_compress(stateshare,n,l,t1,r,y1,subbyte_share_call_compress);
  shiftrows_share(stateshare,n);
  addroundkey_share(stateshare,wshare,10,n);

  for(i=0;i<16;i++)
  {
    out[i]=decode(stateshare[i],n);
      free(stateshare[i]);
  }
}



int run_aes_share_compress_t1_once(byte in[16],byte out[16],byte key[16],int n,int l,byte* t1,byte* r,byte* y1,void (*subbyte_share_call_compress)(byte *,byte,byte,byte *,byte *,byte*),int nt)
{
  int i;
  byte w[176];
  byte *wshare[176];


  keyexpansion(key,w);

  for(i=0;i<176;i++)
  {
    wshare[i]=(byte *) malloc(n*sizeof(byte));
    share(w[i],wshare[i],n);
    refresh(wshare[i],n);
  }

  for(i=0;i<nt;i++)
    aes_share_subkeys_compress(in,out,wshare,n,l,t1,r,y1,subbyte_share_call_compress);


  for(i=0;i<176;i++)
    free(wshare[i]);

  return (double) (0.00) ;
}

void subbytestate_share_compress_all(byte *stateshare[16],int n,int l,byte *t1,byte *r,byte *y1,byte *x_all,int j,void (*subbyte_share_call_compress)(byte *,byte,byte,byte *,byte *,byte *,byte *,int))
{
  int i;
  for(i=0;i<16;i++)
    subbyte_share_call_compress(stateshare[i],l,n,t1,r,y1,x_all,(16*j+i));
}



void aes_share_subkeys_compress_all(byte in[16],byte out[16],byte *wshare[176],int n,int l,byte *t1,byte *r,byte *y1,byte *x_all,void (*subbyte_share_call_compress)(byte *,byte,byte,byte *,byte *,byte *,byte *,int))
	{
  int i;
  int round=0;

  byte *stateshare[16];

  for(i=0;i<16;i++)
  {
    stateshare[i]=(byte*) malloc(n*sizeof(byte));
    share(in[i],stateshare[i],n);
    refresh(stateshare[i],n);
  }

  addroundkey_share(stateshare,wshare,0,n);

  for(round=1;round<10;round++)
  {
    //printf("Break point round: %d \n",round);
    subbytestate_share_compress_all(stateshare,n,l,t1,r,y1,x_all,(round-1),subbyte_share_call_compress);
    shiftrows_share(stateshare,n);
    mixcolumns_share(stateshare,n);
    addroundkey_share(stateshare,wshare,round,n);
  }

  subbytestate_share_compress_all(stateshare,n,l,t1,r,y1,x_all,(round-1),subbyte_share_call_compress);
  shiftrows_share(stateshare,n);
  addroundkey_share(stateshare,wshare,10,n);

  for(i=0;i<16;i++)
  {
    out[i]=decode(stateshare[i],n);
      free(stateshare[i]);
  }
}




int run_aes_share_compress_t1_all(byte in[16],byte out[16],byte key[16],int n,int l,byte *t1,byte *r,byte* y1,byte *x_all,void (*subbyte_share_call_compress)(byte *,byte,byte,byte *,byte *,byte *,byte *,int),int nt){
//(byte *a,byte l,byte n,byte *t1,byte *r,byte *y1,byte *x_all,int j)

  int i;
  byte w[176];
  byte *wshare[176];


  keyexpansion(key,w);

  for(i=0;i<176;i++)
  {
    wshare[i]=(byte *) malloc(n*sizeof(byte));
    share(w[i],wshare[i],n);
    refresh(wshare[i],n);
  }


  for(i=0;i<nt;i++)
    aes_share_subkeys_compress_all(in,out,wshare,n,l,t1,r,y1,x_all,subbyte_share_call_compress);


  for(i=0;i<176;i++)
    free(wshare[i]);

  return (double) (0.00) ;




}

