# Group : Anas Klou and Cedrix Watio Tadjiofouo
# Ex1
## Q1.
the function xtime compute the product of an element of $F_2[X]/X^8 + X^4 + X^3 + X + 1$ and $X$ modulo $X^8 + X^4 + X^3 + X + 1$

```c 
uint8_t xtime(uint8_t p)
{
	uint8_t m = p >> 7;

	m ^= 1;
	m -= 1;
	m &= 0x7B;

	return ((p << 1) ^ m);
}
```

## Q2.
the implementation of prev_aes128_round_key function
```c
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
the function that test the correctness of our implementaion is : `test_prev_key_function(void) `
```

## Q3.
if $k_1=k_2$  the cipher will be always 0

```c
void keyed_function(uint8_t block[AES_BLOCK_SIZE],const uint8_t key_1[AES_128_KEY_SIZE],const uint8_t key_2[AES_128_KEY_SIZE]){
	uint8_t block_1[AES_BLOCK_SIZE] = {0};
	for(int i=0; i<AES_BLOCK_SIZE;++i){
		block_1[i] = block[i];
	}
	aes128_enc(block_1,key_1,3,1);
	aes128_enc(block,key_2,3,1);
	for(int i=0; i<AES_BLOCK_SIZE;++i){
		block[i] = block[i] ^ block_1[i];
	}
}
```

# Exo 2 :

## Q.1 
Look the full_attack function
## Q.2 
The use of different format for F_8 it doesn't matter,we just must redefine the multiplication by X and maybe the addition also.

