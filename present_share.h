void addroundkey_present_share(byte *state[8],byte *key[10],int n);
void sbox_present_share(byte *state[8],int n,byte l,int round);
void keyschedule_present_share(byte *key,int round);
void permute_present_share(byte *state[8],int n);
