# second-order-table-compression
Second-order lookup table based compression scheme 

The provided c code is to run the second-order look-up table compression scheme for AES-128 and PRESENT, for various compression levels (l) ranging from l=1 to 7.
The proposed lookup table countermeasure is shown to be 2-SNI secure against a second-order DPA attack.

The target device for the code is FRDM-K64f from NXP and microcontroller on the target architecture is MK64FN1M0VLL12.
The code makes use of RNGA module built-in to the microcontroller for random number generation.

The code for header files aes.h, aes_share.h, aes_rp.h, share.h and souce code files aes.c, aes_share.c, aes_rp.c and share.c are taken from the public github repository https://github.com/coron/htable. Few methods from these files are customized according to the target architecture requirements.

The code for unmasked PRESENT is from http://www.lightweightcrypto.org/implementations.php.

Repository also contains the code for 8-bit masked bitsliced AES-128.

Notes:

The key scheduling is not secured against DPA attacks and can be imagined as a black-box (means can not be probed by a DPA attacker).
The RNGA module is microcontroller specific and need the device specific files for compiling the code.






