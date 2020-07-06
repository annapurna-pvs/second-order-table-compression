//Code for random number generation. Author Annapurna Valiveti

#include "board.h"
#include "fsl_rnga.h"
#include "fsl_debug_console.h"

#include "rand_k64.h"

RNG_Type *const base =(RNG_Type *) ((char *)0+ 0x40029000u); //RNG_base register initialisation

void rand_in(){

		//RNGA initialisation code
		RNGA_Init(base);
		rnga_mode_t mode;
		status_t flag;
		mode=0U;
		RNGA_SetMode(base,mode);

}

void gen_rand(char *arr,int size){ //Populate arr with required number of random bytes using RNGA
		
		int j;
		status_t flag;
	
		for(j=0;j<size;j++){
			arr[j]=0;
			}
	
		flag=RNGA_GetRandomData(base,arr,size);
}

void rand_dein()
{
			RNGA_Deinit(base);	
}