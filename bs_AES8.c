//8-bt masked bitsliced implementation of AES-128. Author Annapurna Valiveti.

#include <stdint.h>
#include "bs_withoutshares.h"
#include "aes.h"
#include "share.h"

#define nshares 3

const byte S=8; //number of bits in input
const byte T=8;//number of bits of register in use

/****************Primitive functions**************/

void MOV8(byte *t,byte *s)
{
	t[0] = s[0];
	t[1] = s[1];
	t[2] = s[2];
}

void XOR8(byte *c,byte *a,byte *b)
{
    byte i;
    //for(i=0;i<nshares;i++)
        c[0] = a[0] ^ b[0];
        c[1] = a[1] ^ b[1];
        c[2] = a[2] ^ b[2];

}

void AND8(byte *c,byte *a,byte *b)
{
    byte i,j;

    for(i=0;i<3;i++)
        c[i]=a[i] & b[i];

    for(i=0;i<3;i++)
    {
        for(j=i+1;j<3;j++)
        {
            byte tmp=xorshf96()%256; // rand();
            byte tmp2=(tmp ^ (a[i] & b[j]) ^ (a[j] & b[i]));
            c[i]^=tmp;
            c[j]^=tmp2;
        }
    }
}


void NOT8(unsigned int *a)	{
    a[0] = a[0] ^ (0xFF);
}



void swap_share8(byte *a,byte *b)
{
   byte i,m;
   for(i=0;i<3;i++)
   {
        m=a[i];
        a[i]=b[i];
        b[i]=m;
   }

}


byte swapBits_share8(byte *n, byte k1, byte k2)//Code snippet taken from https://www.geeksforgeeks.org/swap-bits-in-a-given-number/.
{
    byte i;
    byte b1,b2,x;

    for(i=0;i<3;i++)
    {

        b1 =  (n[i] >> k1) & 1;
        b2 =  (n[i] >> k2) & 1;
        x = (b1 ^ b2);

        x = (x << k1) | (x << k2);
        n[i] = (n[i] ^ x)&(0xFF);//the mask depends on the number of bits in target representation
    }
}


void left_swap_r(byte *state[16])
{
	byte temp[3],temp1[3];
	int i;

	for(i=0;i<8;i++)
	{
		MOV8(temp1,state[2*i]);//odd bits
		MOV8(temp,state[2*i+1]);//even bits

		swapBits_share8(temp1,6,7);
		swapBits_share8(temp1,5,4);
		swapBits_share8(temp1,3,2);
		swapBits_share8(temp1,1,0);

		swap_share8(temp,temp1);

        MOV8(state[2*i],temp1);
        MOV8(state[2*i+1],temp);
	}
}

/************8-bit Encodings**********************/

void encode_share8(byte *bit_array[16],byte *arr_b[16],byte n) //Pack even and odd bits in different arrays
{
    int i,k,t,j=T-1,l=S-1,m;

    for(m=0;m<n;m++)
    {
        l=S-1;
        for(k=0;k<8;k++)
        {
           arr_b[2*k][m]=0;
           arr_b[2*k+1][m]=0;
           j=T-1;

            for(i=0;i<8;i++)
            {
                t=(1 & (bit_array[2*i][m] >> l));
                arr_b[2*k][m]=arr_b[2*k][m]+t*pow(2,j);

                t=(1 & (bit_array[2*i+1][m] >> l));
                arr_b[2*k+1][m]=arr_b[2*k+1][m]+t*pow(2,j);

                j--;
            }

            l--;
        }
    }
}



void decode_share8(byte *bit_array[16],byte *arr_b[16],byte n)
{
    byte i,k,t,j=0,pos=T-1,l=S-1,m;
    for(m=0;m<n;m++)
    {
        pos=T-1;
        for(i=0;i<8;i++)
        {

            bit_array[2*i][m]=0;
            bit_array[2*i+1][m]=0;
            l=S-1;
            for(k=0;k<8;k++)
            {

                t=(1&(arr_b[2*k][m]>>pos));
                bit_array[2*i][m]=bit_array[2*i][m]+t*pow(2,l);

                t=(1&(arr_b[2*k+1][m]>>pos));
                bit_array[2*i+1][m]=bit_array[2*i+1][m]+t*pow(2,l);

                l--;
            }
            pos--;
        }
    }
}

void encode_bskey_share8(byte *bit_array[176],byte *arr_b[176],byte n)
{

    byte i,k,t,j=7,l=0,row,m;
    byte num=16;//Number of values in target bitslice
    for(m=0;m<n;m++)
    {
        for(row=0;row<11;row++)
        {
            l=7;
            for(k=0;k<8;k++)
            {
                arr_b[num*row+2*k][m]=0;
                arr_b[num*row+2*k+1][m]=0;
                j=7;

                for(i=0;i<8;i++)
                {

                    t=(1 & (bit_array[num*row+2*i][m] >> l));
                    arr_b[num*row+2*k][m]=arr_b[num*row+2*k][m]+t*pow(2,j);

                    t=(1 & (bit_array[num*row+2*i+1][m] >> l));
                    arr_b[num*row+2*k+1][m]=arr_b[num*row+2*k+1][m]+t*pow(2,j);

                    j--;
                }

                l--;
            }

        }
    }
}

/*************Round functions***************/

void bs_addroundkey_share8(byte *state[16],byte *bs_key[176],byte round,byte n)
{
	int i;
	for(i=0; i<16; i++)
		XOR8(state[i],state[i],bs_key[round*16+i]);
}


void bs_shiftrows_share8(byte *X[16],byte n)
{
	byte i;
	for(i=0;i<8;i++)
	{//for each bit in a byte

        swapBits_share8(X[2*i+1],1,7);//first
		swapBits_share8(X[2*i+1],3,5);//first
		swapBits_share8(X[2*i+1],7,3);//first

		swapBits_share8(X[2*i+1],4,6);
		swapBits_share8(X[2*i+1],0,2);
		swapBits_share8(X[2*i+1],6,2);

	    swapBits_share8(X[2*i],6,2);//second
		swapBits_share8(X[2*i],4,0);//second

    }

}


void bs_mixcol_share8(byte *state[16],byte n)
{
    byte *temp[16],*temp0,*temp1;
	byte *of_odd,*of_even,i,t1;

	for(i=0;i<16;i++)
        temp[i]=(byte*) malloc(n*sizeof(byte));

    temp0=(byte*) malloc(n*sizeof(byte));
    temp1=(byte*) malloc(n*sizeof(byte));
    of_odd=(byte*) malloc(n*sizeof(byte));
    of_even=(byte*) malloc(n*sizeof(byte));

	MOV8(temp0,state[0]);//odd
	MOV8(temp1,state[1]);//even

	swapBits_share8(temp0,6,7);
    swapBits_share8(temp0,4,5);
    swapBits_share8(temp0,2,3);
    swapBits_share8(temp0,0,1);

	swap_share8(temp0,temp1);

	XOR8(of_odd, state[0],temp0);
	XOR8(of_even, state[1],temp1);

	for(i=0;i<7;i++)
    {
        MOV8(temp[2*i],state[2*i+2]);
        MOV8(temp[2*i+1],state[2*i+3]);
    }

	left_swap_r(state);//shift by 1

	for(i=0;i<8;i++)
	{
		XOR8(temp[2*i],temp[2*i],state[((2*i+2)%16)]);
        XOR8(temp[2*i+1],temp[2*i+1],state[((2*i+3)%16)]);
	}

    XOR8(temp[6],temp[6],of_odd);
    XOR8(temp[7],temp[7],of_even);

    XOR8(temp[8],temp[8],of_odd);
    XOR8(temp[9],temp[9],of_even);

    XOR8(temp[12],temp[12],of_odd);
    XOR8(temp[13],temp[13],of_even);

    MOV8(temp[14],of_odd);
    MOV8(temp[15],of_even);


	for(i=0;i<16;i++)
	{
        XOR8(temp[i],temp[i],state[i]);
	}

	left_swap_r(state);//Shift by 2

	for(i=0;i<16;i++)
	{

		 XOR8(temp[i],temp[i],state[i]);
	}

	left_swap_r(state);//Shift by 3

	for(i=0;i<16;i++)
	{
		 XOR8(temp[i],temp[i],state[i]);
	}

   for(i=0;i<16;i++)
        MOV8(state[i],temp[i]);

}


void bs_sbox_share8(byte *X1[16],byte n)
{
	byte* Y[22];
	byte* T[68];
	byte* Z[18];
	byte* S[8];
	byte* X[8];
	byte i;

	for(i=0;i<22;i++)
	{
		Y[i]=(byte*) malloc(n*sizeof(byte));
	}

	for(i=0;i<68;i++)
	{
		T[i]=(byte*) malloc(n*sizeof(byte));
	}
	for(i=0;i<18;i++)
	{
		Z[i]=(byte*) malloc(n*sizeof(byte));
	}
	for(i=0;i<8;i++)
	{
	    S[i]=(byte*) malloc(n*sizeof(byte));
		X[i]=(byte*) malloc(n*sizeof(byte));
	}


    MOV8( X[0],X1[0]);//compute S-box circuit on even bytes first
    MOV8( X[1],X1[2]);
    MOV8( X[2],X1[4]);
    MOV8( X[3],X1[6]);
    MOV8( X[4],X1[8]);
    MOV8( X[5],X1[10]);
    MOV8( X[6],X1[12]);
    MOV8( X[7],X1[14]);

//top linear
XOR8(Y[14] , X[3] , X[5]);
XOR8(Y[13] , X[0] , X[6]);
XOR8(Y[12] , Y[13] , Y[14]);
XOR8(Y[9] , X[0] , X[3]);
XOR8(Y[8] , X[0] , X[5]);
XOR8(T[0] , X[1] , X[2]);
XOR8(Y[1] , T[0] , X[7]);
XOR8(Y[4] , Y[1] , X[3]);
XOR8(Y[2] , Y[1] , X[0]);
XOR8(Y[5] , Y[1] , X[6]);
XOR8(T[1] , X[4] , Y[12]);
XOR8(Y[3] , Y[5] , Y[8]);
XOR8(Y[15] , T[1] , X[5]);
XOR8(Y[20] , T[1] , X[1]);
XOR8(Y[6] , Y[15] , X[7]);
XOR8(Y[10] , Y[15] , T[0]);
XOR8(Y[11] , Y[20] , Y[9]);
XOR8(Y[7] , X[7] , Y[11]);
XOR8(Y[17] , Y[10] , Y[11]);
XOR8(Y[19] , Y[10] , Y[8]);
XOR8(Y[16] , T[0] , Y[11]);
XOR8(Y[21] , Y[13] , Y[16]);
XOR8(Y[18] , X[0] , Y[16]);


//middle non-linear

AND8(T[2] , Y[12] , Y[15]);
AND8(T[3] , Y[3] , Y[6]);
AND8(T[5] , Y[4] , X[7] );
AND8(T[7] , Y[13] , Y[16]);
AND8(T[8] , Y[5] , Y[1] );
AND8(T[10] , Y[2] , Y[7] );
AND8(T[12] , Y[9] , Y[11] );
AND8(T[13] , Y[14] , Y[17]);
XOR8(T[4] , T[3] , T[2] );
XOR8(T[6] , T[5] , T[2]);
XOR8(T[9] , T[8] , T[7]);
XOR8(T[11] , T[10] , T[7]);
XOR8(T[14] , T[13] , T[12]);
XOR8(T[17] , T[4] , T[14]);
XOR8(T[19] , T[9] , T[14] );
XOR8(T[21] , T[17] , Y[20]);

XOR8(T[23] , T[19] , Y[21] );
AND8(T[15] , Y[8] , Y[10]);
AND8(T[26] , T[21] , T[23]);
XOR8(T[16] , T[15] , T[12]);
XOR8(T[18] , T[6] , T[16]);
XOR8(T[20] , T[11] , T[16]);
XOR8(T[24] , T[20] , Y[18]);
XOR8(T[30] , T[23] , T[24]);
XOR8(T[22] , T[18] , Y[19]);
XOR8(T[25] , T[21] , T[22]);
XOR8(T[27] , T[24] , T[26]);
XOR8(T[31] , T[22] , T[26]);
AND8(T[28] , T[25] , T[27]);
AND8(T[32] , T[31] , T[30]);
XOR8(T[29] , T[28] , T[22]);
XOR8(T[33] , T[32] , T[24]);
XOR8(T[34] , T[23] , T[33]);
XOR8(T[35] , T[27] , T[33] );
XOR8(T[42] , T[29] , T[33]);
AND8(Z[14] , T[29] , Y[2]);
AND8(T[36] , T[24] , T[35]);
XOR8(T[37] , T[36] , T[34]);
XOR8(T[38] , T[27] , T[36]);
AND8(T[39] , T[29] , T[38]);
AND8(Z[5] , T[29] , Y[7]);


XOR8(T[44] , T[33] , T[37] );
XOR8(T[40] , T[25] , T[39]);
XOR8(T[41] , T[40] , T[37]);
XOR8(T[43] , T[29] , T[40]);
XOR8(T[45] , T[42] , T[41]);
AND8(Z[0] , T[44] , Y[15]);
AND8(Z[1] , T[37] , Y[6]);

AND8(Z[2] , T[33] , X[7]);
AND8(Z[3] , T[43] , Y[16]);
AND8(Z[4] , T[40] , Y[1]);
AND8(Z[6] , T[42] , Y[11]);
AND8(Z[7] , T[45] , Y[17]);
AND8(Z[8] , T[41] , Y[10]);
AND8(Z[9] , T[44] , Y[12]);
AND8(Z[10] , T[37] , Y[3]);
AND8(Z[11] , T[33] , Y[4]);
AND8(Z[12] , T[43] , Y[13]);
AND8(Z[13] , T[40] , Y[5]);
AND8(Z[15] , T[42] , Y[9]);
AND8(Z[16] , T[45] , Y[14]);
AND8(Z[17] , T[41] , Y[8]);

//bottom linear
XOR8(T[46] , Z[15] , Z[16]);
XOR8(T[55] , Z[16] , Z[17] );
XOR8(T[52] , Z[7] , Z[8]);
XOR8(T[54] , Z[6] , Z[7]);
XOR8(T[58] , Z[4] , T[46]);
XOR8(T[59] , Z[3] , T[54] );
XOR8(T[64] , Z[4] , T[59]);
XOR8(T[47] , Z[10] , Z[11]);

XOR8(T[49] , Z[9] , Z[10]);
XOR8(T[63] , T[49] , T[58] );
XOR8(T[66] , Z[1], T[63]);
XOR8(T[62] , T[52] , T[58]);
XOR8(T[53] , Z[0] , Z[3]);
XOR8(T[50] , Z[2] , Z[12] );
XOR8(T[57] , T[50] , T[53]);
XOR8(T[60] , T[46] , T[57] );

XOR8(T[61] , Z[14] , T[57]);
XOR8(T[65] , T[61] , T[62] );
XOR8(S[0] , T[59] , T[63]);
XOR8(T[51] , Z[2] , Z[5] );
XOR8(S[4] , T[51] , T[66]);
XOR8(S[5] , T[47] , T[65] );
XOR8(T[67] , T[64] , T[65]);

XOR8(S[2] , T[55] , T[67]);

NOT8(S[2]);

XOR8(T[48] , Z[5] , Z[13]);
XOR8(T[56] , Z[12] , T[48]);
XOR8(S[3] , T[53] , T[66]);
XOR8(S[1] , T[64] , S[3]);

NOT8(S[1]);
XOR8(S[6] , T[56], T[62]);
NOT8(S[6]);
XOR8(S[7] , T[48], T[60]);
NOT8(S[7]);

MOV8(X1[0] ,S[0]);
MOV8(X1[2] , S[1]);
MOV8(X1[4] , S[2]);
MOV8(X1[6] , S[3]);
MOV8(X1[8] , S[4]);
MOV8(X1[10] , S[5]);
MOV8(X1[12] , S[6]);
MOV8(X1[14] , S[7]);


 MOV8(X[0],X1[1]);//compute S-box circuit on odd bytes next
 MOV8(X[1],X1[3]);
 MOV8(X[2],X1[5]);
 MOV8(X[3],X1[7]);
 MOV8(X[4],X1[9]);
 MOV8(X[5],X1[11]);
 MOV8(X[6],X1[13]);
 MOV8(X[7],X1[15]);


//top linear
XOR8(Y[14] , X[3] , X[5]);
XOR8(Y[13] , X[0] , X[6]);
XOR8(Y[12] , Y[13] , Y[14]);
XOR8(Y[9] , X[0] , X[3]);
XOR8(Y[8] , X[0] , X[5]);
XOR8(T[0] , X[1] , X[2]);
XOR8(Y[1] , T[0] , X[7]);
XOR8(Y[4] , Y[1] , X[3]);
XOR8(Y[2] , Y[1] , X[0]);
XOR8(Y[5] , Y[1] , X[6]);
XOR8(T[1] , X[4] , Y[12]);
XOR8(Y[3] , Y[5] , Y[8]);
XOR8(Y[15] , T[1] , X[5]);
XOR8(Y[20] , T[1] , X[1]);
XOR8(Y[6] , Y[15] , X[7]);
XOR8(Y[10] , Y[15] , T[0]);
XOR8(Y[11] , Y[20] , Y[9]);
XOR8(Y[7] , X[7] , Y[11]);
XOR8(Y[17] , Y[10] , Y[11]);
XOR8(Y[19] , Y[10] , Y[8]);
XOR8(Y[16] , T[0] , Y[11]);
XOR8(Y[21] , Y[13] , Y[16]);
XOR8(Y[18] , X[0] , Y[16]);


//middle non-linear

AND8(T[2] , Y[12] , Y[15]);
AND8(T[3] , Y[3] , Y[6]);
AND8(T[5] , Y[4] , X[7] );
AND8(T[7] , Y[13] , Y[16]);
AND8(T[8] , Y[5] , Y[1] );
AND8(T[10] , Y[2] , Y[7] );
AND8(T[12] , Y[9] , Y[11] );
AND8(T[13] , Y[14] , Y[17]);
XOR8(T[4] , T[3] , T[2] );
XOR8(T[6] , T[5] , T[2]);
XOR8(T[9] , T[8] , T[7]);
XOR8(T[11] , T[10] , T[7]);
XOR8(T[14] , T[13] , T[12]);
XOR8(T[17] , T[4] , T[14]);
XOR8(T[19] , T[9] , T[14] );
XOR8(T[21] , T[17] , Y[20]);

XOR8(T[23] , T[19] , Y[21] );
AND8(T[15] , Y[8] , Y[10]);
AND8(T[26] , T[21] , T[23]);
XOR8(T[16] , T[15] , T[12]);
XOR8(T[18] , T[6] , T[16]);
XOR8(T[20] , T[11] , T[16]);
XOR8(T[24] , T[20] , Y[18]);
XOR8(T[30] , T[23] , T[24]);
XOR8(T[22] , T[18] , Y[19]);
XOR8(T[25] , T[21] , T[22]);
XOR8(T[27] , T[24] , T[26]);
XOR8(T[31] , T[22] , T[26]);
AND8(T[28] , T[25] , T[27]);
AND8(T[32] , T[31] , T[30]);
XOR8(T[29] , T[28] , T[22]);
XOR8(T[33] , T[32] , T[24]);
XOR8(T[34] , T[23] , T[33]);
XOR8(T[35] , T[27] , T[33] );
XOR8(T[42] , T[29] , T[33]);
AND8(Z[14] , T[29] , Y[2]);
AND8(T[36] , T[24] , T[35]);
XOR8(T[37] , T[36] , T[34]);
XOR8(T[38] , T[27] , T[36]);
AND8(T[39] , T[29] , T[38]);
AND8(Z[5] , T[29] , Y[7]);


XOR8(T[44] , T[33] , T[37] );
XOR8(T[40] , T[25] , T[39]);
XOR8(T[41] , T[40] , T[37]);
XOR8(T[43] , T[29] , T[40]);
XOR8(T[45] , T[42] , T[41]);
AND8(Z[0] , T[44] , Y[15]);
AND8(Z[1] , T[37] , Y[6]);

AND8(Z[2] , T[33] , X[7]);
AND8(Z[3] , T[43] , Y[16]);
AND8(Z[4] , T[40] , Y[1]);
AND8(Z[6] , T[42] , Y[11]);
AND8(Z[7] , T[45] , Y[17]);
AND8(Z[8] , T[41] , Y[10]);
AND8(Z[9] , T[44] , Y[12]);
AND8(Z[10] , T[37] , Y[3]);
AND8(Z[11] , T[33] , Y[4]);
AND8(Z[12] , T[43] , Y[13]);
AND8(Z[13] , T[40] , Y[5]);
AND8(Z[15] , T[42] , Y[9]);
AND8(Z[16] , T[45] , Y[14]);
AND8(Z[17] , T[41] , Y[8]);

//bottom linear
XOR8(T[46] , Z[15] , Z[16]);
XOR8(T[55] , Z[16] , Z[17] );
XOR8(T[52] , Z[7] , Z[8]);
XOR8(T[54] , Z[6] , Z[7]);
XOR8(T[58] , Z[4] , T[46]);
XOR8(T[59] , Z[3] , T[54] );
XOR8(T[64] , Z[4] , T[59]);
XOR8(T[47] , Z[10] , Z[11] );

XOR8(T[49] , Z[9] , Z[10]);
XOR8(T[63] , T[49] , T[58] );
XOR8(T[66] , Z[1], T[63]);
XOR8(T[62] , T[52] , T[58]);
XOR8(T[53] , Z[0] , Z[3]);
XOR8(T[50] , Z[2] , Z[12] );
XOR8(T[57] , T[50] , T[53]);
XOR8(T[60] , T[46] , T[57] );

XOR8(T[61] , Z[14] , T[57]);
XOR8(T[65] , T[61] , T[62] );
XOR8(S[0] , T[59] , T[63]);
XOR8(T[51] , Z[2] , Z[5] );
XOR8(S[4] , T[51] , T[66]);
XOR8(S[5] , T[47] , T[65] );
XOR8(T[67] , T[64] , T[65]);

XOR8(S[2] , T[55] , T[67]);

NOT8(S[2]);

XOR8(T[48] , Z[5] , Z[13]);
XOR8(T[56] , Z[12] , T[48]);
XOR8(S[3] , T[53] , T[66]);
XOR8(S[1] , T[64] , S[3]);

NOT8(S[1]);
XOR8(S[6] , T[56], T[62]);
NOT8(S[6]);
XOR8(S[7] , T[48], T[60]);
NOT8(S[7]);


MOV8(X1[1] , S[0]);
MOV8(X1[3] , S[1]);
MOV8(X1[5] , S[2]);
MOV8(X1[7] , S[3]);
MOV8(X1[9] , S[4]);
MOV8(X1[11] , S[5]);
MOV8(X1[13] , S[6]);
MOV8(X1[15] , S[7]);


for(i=0;i<22;i++)
	{
		free(Y[i]);
	}

	for(i=0;i<68;i++)
	{
		free(T[i]);
	}
	for(i=0;i<18;i++)
	{
		free(Z[i]);
	}
	for(i=0;i<8;i++)
	{
		free(S[i]);
		free(X[i]);
	}

}
