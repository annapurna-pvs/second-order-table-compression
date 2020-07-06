//Lookup table based S-box compression. Author Annapurna Valiveti.

#include <stdio.h>
#include "present.h"


//l=2
#define gl 3 //(4-l+1)
#define r_size 4//pow(2,l);
#define t_size 4
#define t1_size 4//pow(2,4-l);
#define total_sbox 496
#define bits 4

//Total 10 rounds for 16 bytes including last round. Total=10*16=160 tables.
byte t1[total_sbox*t1_size/2]; //Each T1 of size 2^(n-l)bytes.
byte r[total_sbox*r_size]; //Random r's to pack of size 2^l bytes.
byte x_shares[total_sbox*2]; //Shares of x used as part of pre-processing.
byte w[total_sbox]; //Random value to shift S-box index.
byte gamma[total_sbox*gl];//Array used to generate output shares using subset-sum technique
byte t_l=t_size;//pow_cus(2,l);
byte t_nl=t1_size/2;//pow_cus(2,(8-l));

byte shift[2]={0,4};
//byte


void gen_rand(byte *a,int n)
{
    int i;
    for(i=0;i<n;i++)
        a[i]=rand()%16;
}

byte s_ibox(byte i, byte u, byte l){

    byte input = (u<<l) | i;
    return sbox_p[input];
}


byte subset_sum(byte b1,int i,byte len){ //y1=subset_sum(b_f,z_gamma,8-l);

    byte j,t1=0,t2,temp;
    t2=b1;
    temp=gamma[i+len];

    for(j=0;j<len;j++){
        t1=t2%2;
        t2=t2/2;
        if(t1){
            temp=temp^gamma[i+j];
        }

    }
    return temp;

}



/************Pre-processing of T1 for 496 S-box calls*******************/

void gen_t1_foral(byte l){

		int z_l,z_nl,z_gamma;
		byte v_f,shr1;
		byte a_f,b_f,k,sbox_pack,temp;
		byte x1_f,x2_f,x1_s;
		int i,j=0,kt=0;
		byte arr[3];
        byte ta,tb,tc;

		gen_rand(w,total_sbox);
		gen_rand(r,total_sbox*t_l);
        gen_rand(gamma,total_sbox*(bits-l+1));

		for(i=0;i<total_sbox;i++)
            w[i]=w[i]%t_l;//second

		for(i=0;i<(total_sbox*t_l);i++)
			r[i] = r[i]>>l;//first n-l bits

		for(i=0;i<total_sbox;i++)
        {
			z_nl=i*t_nl;
			z_l=i*t_l;
			z_gamma=i*(bits-l+1);

			gen_rand(arr,3);
			x_shares[j]=arr[0];
			x_shares[j+1]=arr[1];


			x1_f = x_shares[j]>>l;//first(x_shares[j], l);
			x2_f = x_shares[j+1]>> l;//first(x_shares[j+1], l);
			x1_s = x_shares[j]%t_l;//second(x_shares[j], l);

			v_f = arr[2]>>l;//random_f(l);
			shr1 = ((x1_f^ v_f)^ x2_f );

			for(a_f = 0; a_f < t1_size; a_f++)
            {
				b_f = (a_f^ shr1);
				ta=b_f/2;
				//t1[ta+z_nl] = 0x0;
				temp=0x0;
                sbox_pack=subset_sum(b_f,z_gamma,bits-l);//Output mask y1

				for(k=0; k<t_l; k++)
                {
					temp = ((a_f^ r[((k^w[i]))+z_l])^ v_f);
					sbox_pack = (sbox_pack^s_ibox((x1_s^k), temp, l));//Packing of 2^l values
				}
				tb=(sbox_pack<<(shift[b_f%2]));
                t1[ta+z_nl] = tb | t1[ta+z_nl];//packing in the same table row
			}
			j=j+2;
		}

}



/*************************On-line table compression*****************************/

void subbyte_htable_compress_T2(byte *a,byte l,byte n,int j){

		int z_l,z_nl,z_gamma;
		byte arr[2];
		byte t2[t_size], y2[t_size];

		byte x11=x_shares[j*2];
		byte x22=x_shares[2*j+1];

		byte iz;

		byte y11_ind;

		gen_rand(arr,1);
		byte v_s = arr[0]%t_l;//random_s(l);

		byte k;

		byte x1_f = x11>>l;//first(x11, l);
		byte x1_s = x11%t_l;//second(x11, l);

		byte x2_f = x22>>l;//first(x22, l);
		byte x2_s = x22%t_l;//second(x22, l);

		byte x3,x3_f,x3_s;

		byte shr2 = ((x1_s^ v_s)^ x2_s);
		byte a_s,itr,b_s,temp,S_xor,si_box_i,sbox_pack;

		byte ta,tb,tc;

		x3= ((a[2]^x11)^a[1]);
		x3=((x3^x22)^a[0]);
		x3_f=x3>>l;
		x3_s=x3%t_l;

		z_l=j*t_l;
		z_nl=j*t_nl;
		z_gamma=j*(bits-l+1);


		gen_rand(y2,t_l);

		for(a_s=0; a_s < t_l; a_s++){

				itr = (x1_s^(x3_s^w[j]));
				b_s = (a_s^ shr2);
				ta=((x3_f^ r[z_l+(itr^a_s)]));
				tb=ta/2;
				tc=((t1[z_nl+tb])>>shift[ta%2])&0x0F;
				temp = (  tc ^ y2[b_s]);
				S_xor = 0x0;

				for(k=0; k<t_l; k++){

					if(k != a_s){ // This loop is to unpack the required S-box value

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
		a[0] = subset_sum(y11_ind,z_gamma,(bits-l));//y11[z_nl+y11_ind];
		a[1] = y2[v_s];
		a[2] = t2[v_s];

}


void addroundkey_present_share(byte *state[8],byte *key[10],int n)
{
    int i,j;
   for(i=0;i<n;i++)
    for(j=0;j<8;j++)
        state[j][i] = state[j][i] ^ key[j+2][i];
}

void sbox_present_share(byte *state[8],int n,byte l,int round)
{
    byte i,j;
    byte *a[2];

    for(i=0;i<2;i++)
        a[i]=(byte*) malloc(n*sizeof(byte));

    for(i=0;i<8;i++)
    {
        for(j=0;j<n;j++)
        {
            a[0][j]=state[i][j]>>4;
            a[1][j]=state[i][j]& 0xF;
        }


        subbyte_htable_compress_T2(a[0],l,n,16*round+2*i);//(16*j+2i),2i=1
        subbyte_htable_compress_T2(a[1],l,n,16*round+2*i+1);

        for(j=0;j<n;j++)
        {
            state[i][j]=a[0][j]<<4|a[1][j];
        }

   }


}


void keyschedule_present_share(byte *key,int round)
{
    byte save1,save2;
    int i;

   		save1  = key[0];
		save2  = key[1];

		for(i=0;i<8;i++)
            key[i] = key[i+2];

		key[8] = save1;
		key[9] = save2;
		save1 = key[0] & 7;								//61-bit left shift

        for(i=0;i<9;i++)
			key[i] = key[i] >> 3 | key[i+1] << 5;

		key[9] = key[9] >> 3 | save1 << 5;
		key[9] = sbox_p[key[9]>>4]<<4 | (key[9] & 0xF);	//S-Box application

		if((round+1) % 2 == 1)							//round counter addition
			key[1] ^= 128;
		key[2] = ((((round+1)>>1) ^ (key[2] & 15)) | (key[2] & 240));

}

void permute_present_share(byte *state[8],int n)
{
    int i,j;
    byte temp[8];

    for(j=0;j<n;j++)
    {

    for(i=0;i<8;i++)
    {
			temp[i] = 0;
	}

	for(i=0;i<64;i++)
	{
		byte position = (16*i) % 63;						//Artithmetic calculation of the pLayer
		if(i == 63)									//exception for bit 63
			position = 63;
		byte element_source		= i / 8;
		byte bit_source 			= i % 8;
		byte element_destination	= position / 8;
		byte bit_destination 	= position % 8;
		temp[element_destination] |= ((state[element_source][j]>>bit_source) & 0x1) << bit_destination;
    }

	for(i=0;i<=7;i++)
			state[i][j] = temp[i];

    }
}


int main_present()
{
	byte key[] ={0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xf};
	byte state[8]={0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d};//{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	byte *stateshare[8],*keyshare[10],state1[8];
    byte i=0;
    int round,n=3,l=2;

    gen_t1_foral(l);

     for(i=0;i<8;i++)
    {
        stateshare[i]=(byte*) malloc(n*sizeof(byte));
        share(state[i],stateshare[i],n);
        refresh(stateshare[i],n);
    }

    for(i=0;i<10;i++)
    {
        keyshare[i]=(byte*) malloc(n*sizeof(byte));
        share(key[i],keyshare[i],n);
        refresh(keyshare[i],n);
    }


    for(round=0;round<31;round++)
    {
        addroundkey_present(state,key);
        addroundkey_present_share(stateshare,keyshare,n);
        sbox_present(state);
        sbox_present_share(stateshare,n,l,round);
        permute_present(state);
        permute_present_share(stateshare,n);
        keyschedule_present(key,round);

        for(i=0;i<10;i++)
        {
            share(key[i],keyshare[i],n);
            refresh(keyshare[i],n);
        }

    }
    addroundkey_present(state,key);
    addroundkey_present_share(stateshare,keyshare,n);

    for(i=0;i<8;i++)
        state1[i]=decode(stateshare[i],n);

	for(i=0;i<8;i++)
    {
        if(state[i]!=state1[i])
        {
            printf("Output is not as expected!! pls check....");
            return 0;
        }

    }

    printf("Obtained matched expected :-\n");

	return 0;
}

