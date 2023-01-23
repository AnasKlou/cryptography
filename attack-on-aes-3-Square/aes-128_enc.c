/*
 * AES-128 Encryption
 * Byte-Oriented
 * On-the-fly key schedule
 * Constant-time XTIME
 */

#include "aes-128_enc.h"

/*
 * Constant-time ``broadcast-based'' multiplication by $a$ in $F_2[X]/X^8 + X^4 + X^3 + X + 1$
 */
uint8_t xtime(uint8_t p)
{
	uint8_t m = p >> 7;

	m ^= 1;
	m -= 1;
	m &= 0x1B;//0x7B;

	return ((p << 1) ^ m);
}

/*
 * The round constants
 */
static const uint8_t RC[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

void aes_round(uint8_t block[AES_BLOCK_SIZE], uint8_t round_key[AES_BLOCK_SIZE], int lastround)
{
	int i;
	uint8_t tmp;

	/*
	 * SubBytes + ShiftRow
	 */
	/* Row 0 */
	block[ 0] = S[block[ 0]];
	block[ 4] = S[block[ 4]];
	block[ 8] = S[block[ 8]];
	block[12] = S[block[12]];
	/* Row 1 */
	tmp = block[1];
	block[ 1] = S[block[ 5]];
	block[ 5] = S[block[ 9]];
	block[ 9] = S[block[13]];
	block[13] = S[tmp];
	/* Row 2 */
	tmp = block[2];
	block[ 2] = S[block[10]];
	block[10] = S[tmp];
	tmp = block[6];
	block[ 6] = S[block[14]];
	block[14] = S[tmp];
	/* Row 3 */
	tmp = block[15];
	block[15] = S[block[11]];
	block[11] = S[block[ 7]];
	block[ 7] = S[block[ 3]];
	block[ 3] = S[tmp];

	/*
	 * MixColumns
	 */
	for (i = lastround; i < 16; i += 4) /* lastround = 16 if it is the last round, 0 otherwise */
	{
		uint8_t *column = block + i;
		uint8_t tmp2 = column[0];
		tmp = column[0] ^ column[1] ^ column[2] ^ column[3];

		column[0] ^= tmp ^ xtime(column[0] ^ column[1]);
		column[1] ^= tmp ^ xtime(column[1] ^ column[2]);
		column[2] ^= tmp ^ xtime(column[2] ^ column[3]);
		column[3] ^= tmp ^ xtime(column[3] ^ tmp2);
	}

	/*
	 * AddRoundKey
	 */
	for (i = 0; i < 16; i++)
	{
		block[i] ^= round_key[i];
	}
}

/*
 * Compute the @(round + 1)-th round key in @next_key, given the @round-th key in @prev_key
 * @round in {0...9}
 * The ``master key'' is the 0-th round key 
 */
void next_aes128_round_key(const uint8_t prev_key[16], uint8_t next_key[16], int round)
{
	int i;

	next_key[0] = prev_key[0] ^ S[prev_key[13]] ^ RC[round];
	next_key[1] = prev_key[1] ^ S[prev_key[14]];
	next_key[2] = prev_key[2] ^ S[prev_key[15]];
	next_key[3] = prev_key[3] ^ S[prev_key[12]];

	for (i = 4; i < 16; i++)
	{
		next_key[i] = prev_key[i] ^ next_key[i - 4];
	}
}

/*
 * Compute the @round-th round key in @prev_key, given the @(round + 1)-th key in @next_key 
 * @round in {0...9}
 * The ``master decryption key'' is the 10-th round key (for a full AES-128)
 */
void prev_aes128_round_key(const uint8_t next_key[16], uint8_t prev_key[16], int round)
{
	int i;

	prev_key[0] = next_key[0] ^ S[next_key[13] ^ next_key[9]] ^ RC[round];
	prev_key[1] = next_key[1] ^ S[next_key[14] ^ next_key[10]];
	prev_key[2] = next_key[2] ^ S[next_key[15] ^ next_key[11]];
	prev_key[3] = next_key[3] ^ S[next_key[12] ^ next_key[8]];

	for (i = 4; i < 16; i++)
	{
		prev_key[i] = next_key[i] ^ next_key[i - 4];
	}
}

/*
 * Encrypt @block with @key over @nrounds. If @lastfull is true, the last round includes MixColumn, otherwise it doesn't.
 * @nrounds <= 10
 */
void aes128_enc(uint8_t block[AES_BLOCK_SIZE], const uint8_t key[AES_128_KEY_SIZE], unsigned nrounds, int lastfull)
{
	uint8_t ekey[32];
	int i, pk, nk;

	for (i = 0; i < 16; i++)
	{
		block[i] ^= key[i];
		ekey[i]   = key[i];
	}
	next_aes128_round_key(ekey, ekey + 16, 0);

	pk = 0;
	nk = 16;
	for (i = 1; i < nrounds; i++)
	{
		aes_round(block, ekey + nk, 0);
		pk = (pk + 16) & 0x10;
		nk = (nk + 16) & 0x10;
		next_aes128_round_key(ekey + pk, ekey + nk, i);
	}
	if (lastfull)
	{
		aes_round(block, ekey + nk, 0);
	}
	else
	{
		aes_round(block, ekey + nk, 16);
	}
}




/*
 * invert 1/2 aes_round 
 */

void aes_invert_half_round(uint8_t block[AES_BLOCK_SIZE],uint8_t round_key[AES_128_KEY_SIZE])
{
	
	int i;
	
	for (i = 0; i < 16; i++)
	{
		block[i] ^= round_key[i];
	}

	uint8_t tmp;

	/*
	 * SubBytes + ShiftRow
	 */
	/* Row 0 */
	block[ 0] = Sinv[block[ 0]];
	block[ 4] = Sinv[block[ 4]];
	block[ 8] = Sinv[block[ 8]];
	block[12] = Sinv[block[12]];

	block[ 1] = Sinv[block[ 1]];
	block[ 2] = Sinv[block[ 2]];
	block[ 3] = Sinv[block[ 3]];
	block[ 5] = Sinv[block[ 5]];
	block[ 6] = Sinv[block[ 6]];

	block[ 7] = Sinv[block[ 7]];
	block[ 9] = Sinv[block[ 9]];
	block[10] = Sinv[block[10]];

	block[11] = Sinv[block[11]];
	block[13] = Sinv[block[13]];
	block[14] = Sinv[block[14]];
	block[15] = Sinv[block[15]];

	
}

/*
 This function take a plaintext, firt it ciphers it with black-box(aes-128 3-rnd 1/2 with unknown key) and then decrypt it with our key 
 in order to get a cipher win aes-128 3-rnd.
*/
uint8_t try_our_key(uint8_t plaintext[AES_BLOCK_SIZE], uint8_t key[AES_128_KEY_SIZE],const uint8_t keyToFind[AES_128_KEY_SIZE],uint8_t block_index){

	uint8_t plaintxt_cp[AES_BLOCK_SIZE] = {0};
	for(int i=0; i<AES_BLOCK_SIZE;++i){
		plaintxt_cp[i] = plaintext[i];
	}
	aes128_enc(plaintxt_cp,keyToFind,4,0);// Black box
	aes_invert_half_round(plaintxt_cp,key);
	return plaintxt_cp[block_index];
}

/*
	This function take encrypt all the possible palintext (by changing each time the value of palintext[block]) with the key we have guessed
	and then we compute the xor of all the those cipher texts.
*/
int aes_attack_block(uint8_t key_to_test[AES_128_KEY_SIZE],uint8_t plaintext[AES_BLOCK_SIZE], const uint8_t keyToFind[AES_128_KEY_SIZE],uint8_t block){
	uint8_t cumul = 0;
	for(int i=0; i<256;++i){
		plaintext[block] = i;
		cumul ^= try_our_key(plaintext,key_to_test,keyToFind,block);
	}
	if(cumul == 0){
		return 1;
	}
	return 0;
}

int test_prev_key_function(void){
	uint8_t key_rnd_5[AES_128_KEY_SIZE] = {0x3c,0xaa,0xa3,0xe8,0xa9, 0x9f, 0x9d, 0xeb, 0x50, 0xf3,0xaf, 0x57,0xad,0xf6,0x22,0xaa};
	uint8_t key_rnd_6[AES_128_KEY_SIZE] = {0x5e,0x39,0x0f,0x7d,0xf7,0xa6,0x92,0x96,0xa7,0x55,0x3d,0xc1,0x0a,0xa3,0x1f,0x6b};
	uint8_t prev_key_6[AES_128_KEY_SIZE] = {0};
	int round = 5;
	prev_aes128_round_key(key_rnd_6,prev_key_6,round);
	for(int i=0; i<AES_128_KEY_SIZE;++i){
		if(prev_key_6[i] != key_rnd_5[i]){
			printf("KO! \n");
			return 0;
		}
	}
	printf("OK! \n");
	return 1;
}


int full_attack(void){
	const uint8_t keyToFind[AES_128_KEY_SIZE] = {0x19,0x85,0xea,0xe3,0x4a,0xb5,0x6b,0x77,0xc8,0xd9,0x02,0xfc,0xcd,0x31,0x87,0x45};//{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	uint8_t plaintext[AES_BLOCK_SIZE] ={0} ;
	uint8_t random_key[AES_128_KEY_SIZE] = {0};
	uint8_t key[AES_128_KEY_SIZE] = {0};
	uint8_t block = 0;
	int positive_val_key = 0;
	
	for(int i=0; i<AES_BLOCK_SIZE;++i){
		plaintext[i] = rand()%256;	
	}
	while (block<AES_BLOCK_SIZE){
		for(int i =0;i<256;++i){
			random_key[block] = i;
			
			positive_val_key = aes_attack_block(random_key,plaintext,keyToFind,block);
			if(positive_val_key == 1){ // the value of that key's block is positive
				for(int j=0; j<AES_BLOCK_SIZE;++j){ // we create another random plaintext to verify that the key is correct
					plaintext[j] = rand()%256;	
				}		
				positive_val_key = aes_attack_block(random_key,plaintext,keyToFind,block);
				if (positive_val_key ==1){ // the key's block is correct nb: we can add more test to be sure but that is enough
					//printf("move to the next block %i \n", block+1);
					break;
				}
			}
		}
		++block;
	}

	for(int j=3;j>=0;--j){// get the key we're looking for 	
		prev_aes128_round_key(random_key,key,j);
		for(int a=0;a<16;++a){
			random_key[a] =  key[a];
		}
	}
	printf("The key gotten with the algo :\n");
	for(int i=0; i<AES_BLOCK_SIZE;++i){
		printf("%2x, ",key[i]);
	}
	printf("\n");
	printf("The key used to encript : \n");
	for(int i=0; i<AES_BLOCK_SIZE;++i){
		printf("%2x, ",keyToFind[i]);
	}
	printf("\n");
	


	return 0;
}

int main(){
	test_prev_key_function();
	full_attack();
	return 0;
}

