//Second-order lookup table based compression. Author Annapurna Valiveti.

#include <stdio.h>

#include "board.h"
#include "rand_k64.h"
#include "aes.h"
#include "share.h"
#include "aes_rp.h"
#include "aes_share.h"


//l=1
#define gl 8 //(8-l+1)
#define r_size 2//pow(2,l);
#define t_size 2//pow(2,l);
#define t1_size 128//pow(2,8-l);
#define choice 1 //1 for table based compression, 2 for rp

//Total 10 rounds for 16 bytes including last round. Total=10*16=160 tables.
byte t1[160*t1_size]; //Each T1 of size 2^(n-l)bytes.
byte r[160*r_size]; //Random r's to pack of size 2^l bytes.
byte x_shares[160*2]; //Shares of x used as part of pre-processing.
byte w[160]; //Random value to shift S-box index.
byte gamma[160*gl];//Array used to generate output shares using subset-sum technique
byte t_l=t_size;//pow_cus(2,l);
byte t_nl=t1_size;//pow_cus(2,(8-l));



byte s_ibox(byte i, byte u, byte l)
{
	byte input = (u<<l) | i;
    return sbox[input];
}


void share_rnga(byte x,byte a[],int n) //Additive secret sharing
{
		int i;
		gen_rand(a,n-1);
		a[n-1]=x;
	
		for(i=0;i<n-1;i++)
			a[n-1]=a[n-1] ^ a[i];
  
}


byte pow_cus(byte base,byte exp) //to compute base^exp
{
		byte i,res=1;
		for(i=0;i<exp;i++)
			res=res*base;

		return res;
}


byte subset_sum(byte b1,int i,byte len) //y1=subset_sum(b_f,z_gamma,8-l);
{
    byte j,t1=0,t2,temp;
    t2=b1;
    temp=gamma[i+len];

    for(j=0;j<len;j++)
	{
        t1=t2%2;
        t2=t2/2;
        if(t1){
            temp=temp^gamma[i+j];
        }

    }
    return temp;

}



/************Pre-processing of T1 for 160 S-box calls*******************/

void gen_t1_foral(byte l)
{
		int z_l,z_nl,z_gamma;
		byte v_f,shr1;
		byte a_f,b_f,k,sbox_pack,temp;
		byte x1_f,x2_f,x1_s;
		int i,j=0;
		byte arr[3];

			
		gen_rand(w,160);
		for(i=0;i<160;i++)
		{
			w[i]=w[i]%t_l;//second
        }
		gen_rand(r,160*t_l);
		
		for(i=0;i<(160*t_l);i++)
		{
			r[i] = r[i]>>l;//first n-l bits

		}

		gen_rand(gamma,160*(8-l+1));

		for(i=0;i<160;i++)
		{

			z_nl=i*t_nl;
			z_l=i*t_l;
			z_gamma=i*(8-l+1);

			gen_rand(arr,3);
			x_shares[j]=arr[0];
			x_shares[j+1]=arr[1];


			x1_f = x_shares[j]>>l;//first(x_shares[j], l);
			x2_f = x_shares[j+1]>> l;//first(x_shares[j+1], l);
			x1_s = x_shares[j]%t_l;//second(x_shares[j], l);

			v_f = arr[2]>>l;//random_f(l);
			shr1 = ((x1_f^ v_f)^ x2_f );

			for(a_f = 0; a_f < t_nl; a_f++)
			{

					b_f = (a_f^ shr1);
					t1[b_f+z_nl] = 0x0;
					temp=0x0;
					sbox_pack=subset_sum(b_f,z_gamma,8-l);//Output mask y1

					for(k=0; k<t_l; k++)
					{

							temp = ((a_f^ r[((k^w[i]))+z_l])^ v_f);
							sbox_pack = (sbox_pack^s_ibox((x1_s^k), temp, l));//Packing of 2^l values
					}
					t1[b_f+z_nl] = sbox_pack;
			}
			j=j+2;
		}

}


/*************************On-line table compression*****************************/

void subbyte_htable_compress_T2(byte *a,byte l,byte n,int j)
{
		int z_l,z_nl,z_gamma;
		byte arr[2];
		byte t2[t_size], y2[t_size];

		byte x11=x_shares[j*2];
		byte x22=x_shares[2*j+1];

		byte iz;

		byte y11_ind;
	
		gen_rand(arr,1);
		byte v_s = arr[0]%t_l;

		byte k;

		byte x1_f = x11>>l;//first(x11, l);
		byte x1_s = x11%t_l;//second(x11, l);

		byte x2_f = x22>>l;//first(x22, l);
		byte x2_s = x22%t_l;//second(x22, l);

		byte x3,x3_f,x3_s;

		byte shr2 = ((x1_s^ v_s)^ x2_s);
		byte a_s,itr,b_s,temp,S_xor,si_box_i,sbox_pack;

		x3= ((a[2]^x11)^a[1]);
		x3=((x3^x22)^a[0]);
		x3_f=x3>>l;
		x3_s=x3%t_l;

		z_l=j*t_l;
		z_nl=j*t_nl;
		z_gamma=j*(8-l+1);


		gen_rand(y2,t_l);
   
		for(a_s=0; a_s < t_l; a_s++)
		{

				itr = (x1_s^(x3_s^w[j]));
				b_s = (a_s^ shr2);
				temp = (  t1[ z_nl+((x3_f^ r[z_l+(itr^a_s)]))] ^ y2[b_s]);
				S_xor = 0x0;

				for(k=0; k<t_l; k++)
				{
						if(k != a_s) // This loop is to unpack the required S-box value
						{
							si_box_i = (x3_s^ k);
							sbox_pack = ((((x3_f^ r[z_l+((itr^ a_s))])^ x1_f)^ r[z_l+((itr^ k))])^ x2_f);
							S_xor = (S_xor^ s_ibox(si_box_i, sbox_pack, l));
						}
				}
				t2[b_s] = (temp^ S_xor);
		}

		iz = (x2_s^(x3_s^w[j]));
		y11_ind = (x3_f^ r[z_l+iz]);

		/* Final shares*/ 
		a[0] = subset_sum(y11_ind,z_gamma,(8-l));//y11[z_nl+y11_ind];
		a[1] = y2[v_s];
		a[2] = t2[v_s];

}


void subbytestate_share_compress1(byte stateshare[16][3],int n,int l,int j)//j indicates round number
{
		int i;
	
		if(choice==1)
			for(i=0;i<16;i++)
			{
				subbyte_htable_compress_T2(stateshare[i],l,n,(16*j+i));//(16*j+i) indicates table index
			}
	
			if(choice==2)
			for(i=0;i<16;i++)
			{
				subbyte_rp_share(stateshare[i],n);
			}
}


void aes_share_subkeys_compress1(byte in[16],byte out[16],byte wshare[176][3],int n,int l)
{
		int i;
		int round=0;

		byte stateshare[16][3];

		for(i=0;i<16;i++)
		{
			share_rnga(in[i],stateshare[i],n);
		}

		addroundkey_share1(stateshare,wshare,0,n);

		for(round=1;round<10;round++)
		{
    
				subbytestate_share_compress1(stateshare,n,l,(round-1));
				shiftrows_share1(stateshare,n);
				mixcolumns_share1(stateshare,n);
				addroundkey_share1(stateshare,wshare,round,n);
		}

		subbytestate_share_compress1(stateshare,n,l,(round-1));
		shiftrows_share1(stateshare,n);
		addroundkey_share1(stateshare,wshare,10,n);

		for(i=0;i<16;i++)
		{
			out[i]=decode(stateshare[i],n);
		}
}


void run_aes_share_compress1(byte in[16],byte out[16],byte key[16],int n,int l,int nt)
{
		int i;
		byte w[176];
		byte wshare[176][3]; // This code implementation of second-order compression, n=3

		keyexpansion(key,w);

		for(i=0;i<176;i++)
		{
			share_rnga(w[i],wshare[i],n);
		}

		for(i=0;i<nt;i++)
			aes_share_subkeys_compress1(in,out,wshare,n,l);
}


/*******************main*****************************************/

int main()
{	
		int nt=10; 
		byte n=3,l=1; //Second-order, n=3. l represents compression parameter.
		int i,k;
		
		/****************Test vectors********************/
		
		byte keyex[16]={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
		byte inex[16]={0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
		byte outex[16]={0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32};

		byte in[16],out[16];
		byte key[16];
		printf("Inside main ...Compression!!!");

		for(i=0;i<16;i++) 
				key[i]=keyex[i];
		
		for(i=0;i<16;i++) 
				in[i]=inex[i];
		
		for(k=0;k<16;k++)
        out[k]=0x0;
  
		//rand initialisation
		rand_in();
	

/*******************Un masked AES***************************/
		run_aes(in,out,key,nt);

/*Compressed AES with pre-processing: T1 with pre-processing and T2 table based*/

		gen_t1_foral(l); //Pre-processing table T1 for all rounds
		run_aes_share_compress1(in,out,key,n,l,nt);//AES with shares

		rand_dein();
		return 0;
}
