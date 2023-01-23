#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include "hashmap.c"
#include "xoshiro256starstar.h"

#define ROTL24_16(x) ((((x) << 16) ^ ((x) >> 8)) & 0xFFFFFF)
#define ROTL24_3(x) ((((x) << 3) ^ ((x) >> 21)) & 0xFFFFFF)

#define ROTL24_8(x) ((((x) << 8) ^ ((x) >> 16)) & 0xFFFFFF)
#define ROTL24_21(x) ((((x) << 21) ^ ((x) >> 3)) & 0xFFFFFF)

#define IV 0x010203040506ULL 


/*
 * the 96-bit key is stored in four 24-bit chunks in the low bits of k[0]...k[3]
 * the 48-bit plaintext is stored in two 24-bit chunks in the low bits of p[0], p[1]
 * the 48-bit ciphertext is written similarly in c
 */
void speck48_96(const uint32_t k[4], const uint32_t p[2], uint32_t c[2])
{
	uint32_t rk[23];
	uint32_t ell[3] = {k[1], k[2], k[3]};

	rk[0] = k[0];

	c[0] = p[0];
	c[1] = p[1];

	/* full key schedule */
	for (unsigned i = 0; i < 22; i++)
	{
		uint32_t new_ell = ((ROTL24_16(ell[0]) + rk[i]) ^ i) & 0xFFFFFF; // addition (+) is done mod 2**24
		rk[i+1] = ROTL24_3(rk[i]) ^ new_ell;
		ell[0] = ell[1];
		ell[1] = ell[2];
		ell[2] = new_ell;
	}


	for (unsigned i = 0; i < 23; i++)
	{
		
		c[0] =  ((ROTL24_16(c[0]) + c[1])^rk[i]) & 0xFFFFFF;
		c[1] = (ROTL24_3(c[1])^c[0]) & 0xFFFFFF ;
	}

	return;
}

int test_sp48(){
	uint32_t k[4] = {0x020100 , 0x0a0908, 0x121110, 0x1a1918};
	uint32_t p[2] = {0x6d2073, 0x696874};
	uint32_t c[2] = {0};
	uint32_t result[2] = {0x735e10, 0xb6445d };
	speck48_96(k,p,c);
	for(int i=0;i<2;++i){
		// printf("c : %x, rsl : %x\n",c[i],result[i]);
		if(c[i] != result[i]){
			printf("sp48 : KO !\n");
			return 0;
		}
	}
	printf("sp48     : OK! \n");
	return 1;
}

/* the inverse cipher */
void speck48_96_inv(const uint32_t k[4], const uint32_t c[2], uint32_t p[2])
{
	uint32_t rk[23];

	uint32_t ell[3] = {k[1], k[2], k[3]};

	rk[0] = k[0];

	p[0] = c[0];
	p[1] = c[1];

	// inverse round
	for (unsigned i = 0; i < 22; i++)
	{
		uint32_t new_ell = ((ROTL24_16(ell[0]) + rk[i]) ^ i) & 0xFFFFFF; // addition (+) is done mod 2**24
		rk[i+1] = ROTL24_3(rk[i]) ^ new_ell;
		ell[0] = ell[1];
		ell[1] = ell[2];
		ell[2] = new_ell;
	}

	for (unsigned i = 0; i < 23; i++)
	{
		// invert what we did in speck48_96
		p[1] = ROTL24_21(p[0]^p[1]);
		p[0] = ROTL24_8(((p[0]^rk[22-i])-p[1]) & 0xFFFFFF);
		
	}
	return;
}

int test_sp48_inv(){
	uint32_t k[4] = {0x020100 , 0x0a0908, 0x121110, 0x1a1918};
	uint32_t p[2] = {0x735e10, 0xb6445d };
	uint32_t c[2] = {0};
	uint32_t result[2] = { 0x6d2073, 0x696874 };
	speck48_96_inv(k,p,c);
	for(int i=0; i<2;++i){
		if(c[i] != result[i]){
			printf("sp48 inv : KO !\n");
			return 0;
		}
	}
	printf("sp48 inv : OK! \n");
	
	return 1;
}



/* The Davies-Meyer compression function based on speck48_96,
 * using an XOR feedforward
 * The input/output chaining value is given on the 48 low bits of a single 64-bit word,
 * whose 24 lower bits are set to the low half of the "plaintext"/"ciphertext" (p[0]/c[0])
 * and whose 24 higher bits are set to the high half (p[1]/c[1])
 */
uint64_t cs48_dm(const uint32_t m[4], const uint64_t h)
{
	/* FILL ME */
	uint32_t c[2] = {0};
	uint32_t p[2] = {0};
	uint64_t result = 0;
	p[0] = h & 0xFFFFFF;
	p[1] = (h >>24) & 0xFFFFFF;
	speck48_96(m,p,c);
	c[0] = c[0]^p[0];
	c[1] = c[1]^p[1];

	result =  c[1];
	result = result <<24 | c[0];
	return result;
}
/*
	Test of cs48_dm
*/
int test_cs48_dm(void){
	uint32_t m[4] = {3, 2, 1, 0};
	uint64_t r = cs48_dm(m,IV);
	uint64_t result  = 0x5DFD97183F91ULL;
	if(result != r){
		printf("cs48_dm   : KO!\n",r);
		return 1;
	}
	printf("cs48_dm : OK! \n");
	return 0;
}

/* assumes message length is fourlen * four blocks of 24 bits, each stored as the low bits of 32-bit words
 * fourlen is stored on 48 bits (as the 48 low bits of a 64-bit word)
 * when padding is include, simply adds one block (96 bits) of padding with fourlen and zeros on higher pos */
uint64_t hs48(const uint32_t *m, uint64_t fourlen, int padding, int verbose)
{
	uint64_t h = IV;
	const uint32_t *mp = m;

	for (uint64_t i = 0; i < fourlen; i++)
	{
		h = cs48_dm(mp, h);
		if (verbose)
			printf("@%llu : %06X %06X %06X %06X => %06llX\n", i, mp[0], mp[1], mp[2], mp[3], h);
		mp += 4;
	}
	if (padding)
	{
		uint32_t pad[4];
		pad[0] = fourlen & 0xFFFFFF;
		pad[1] = (fourlen >> 24) & 0xFFFFFF;
		pad[2] = 0;
		pad[3] = 0;
		h = cs48_dm(pad, h);
		if (verbose)
			printf("@%llu : %06X %06X %06X %06X => %06llX\n", fourlen, pad[0], pad[1], pad[2], pad[3], h);
	}

	return h;
}

/*
 Computes the unique fixed-point for cs48_dm for the message m 
	the fixed point of m is plaintext of the cipher c= {0,0}
*/
uint64_t get_cs48_dm_fp(const uint32_t m[4])
{

	uint32_t c[2] = {0};
	uint32_t p[2] = {0};	
	uint64_t result = 0;
	speck48_96_inv(m,p,c);
	result =  c[1];
	result = (result <<24) | c[0];
	// printf("point fixe %lx \n",result);
	return result;

}

int test_cs48_dm_fp(void){
	uint32_t m[4] = {0,1,2,3};
	uint64_t fp_1 = get_cs48_dm_fp(m);
	printf("pt fixe 1 %x \n",fp_1);
	uint64_t fp_2 = cs48_dm(m,fp_1);
	printf("pt fixe 2 %x \n",fp_2);
	if(fp_1 == fp_2){
		printf("cs40_dm_fp : OK!\n");
		return 1;
	}
	printf("cs40_dm_fp : KO! \n");
	return 0;
}


/*
 * generate random message of 96 bits 
 */
int generate_msg_hash(uint32_t m[4]){
	uint64_t m1;
	m1 =  xoshiro256starstar_random();
	m[3] = m1 & 0xFFFFFF;
	m[2] = (m1>>32) & 0xFFFFFF;
	m1 =  xoshiro256starstar_random();
	m[1] = m1 & 0xFFFFFF;
	m[0] = (m1>>32) & 0xFFFFFF;
	return 0;
}

/*
 * This function is used by the hashmap used in find_exp_mess function. When we want to set or to get an element from the hashmap
 * index parameter is used to spycify which hash we will use if index==0 means that the hash while setting
 * otherwise the hash is used while getting
 */
uint64_t msg_hash(const void *item, uint64_t seed0, uint64_t seed1,int index) {
	const uint32_t *m = item;
	uint64_t h = 0;
	if(index == 0){// if we want to set an item
		h = cs48_dm(m,IV);
	}
	else{// if we want to get an item
		h = get_cs48_dm_fp(m);
	}
	return h;
}
/*
 * this function is used when we tried to get an element from the hahsmap
 * this comparaison is based on the fact that get_cs48_dm_fp(m_1)==cs48_dm(m_2,IV)
 */
int compare_msg(const void *a, const void *b, void *udata){
	const uint32_t *m_1 = a;
	const uint32_t *m_2 = b;
	uint64_t h = get_cs48_dm_fp(m_1);
	if (cs48_dm(m_2,IV) == h){
		return 0;
	}
	return 1;
}

/* Finds a two-block expandable message for hs48, using a fixed-point
 * That is, computes m1, m2 s.t. hs48_nopad(m1||m2) = hs48_nopad(m1||m2^*),
 * where hs48_nopad is hs48 with no padding
*/
uint64_t find_exp_mess(uint32_t m1[4], uint32_t m2[4])
{
	uint64_t N  = 1ULL << 24;
	uint64_t pt_fixe =0;
	struct hashmap *map = hashmap_new(sizeof(uint32_t)*4, 0, 0, 0, 
                                     msg_hash, compare_msg, NULL, NULL);// This map is full of keys (words of 96 bits)
	for(uint64_t i=0; i<N; ++i ){
		uint32_t msg[4] ;
		generate_msg_hash(msg);
		// printf("msg : %x %x %x %x fp = %lx \n",msg[0],msg[1],msg[2],msg[3],cs48_dm(msg,IV));
		hashmap_set(map,msg);
	}
	int k = 0;
	uint32_t *msg1 = m1;
	uint64_t a=  1ULL << 48;
	while(a>0){
		generate_msg_hash(m2);
		// printf("m2 : %x %x %x %x fp = %lx \n",m2[0],m2[1],m2[2],m2[3],get_cs48_dm_fp(m2));
		msg1 = hashmap_get(map,m2);// try to get element from the map s.t get_cs48_dm_fp(m2)==cs48_dm(msg1,IV)
		if (msg1) {
			m1[0] = msg1[0];
			m1[1] = msg1[1];
			m1[2] = msg1[2];
			m1[3] = msg1[3];
        	// printf("m1 : %x %x %x %x \n",m1[0],m1[1],m1[2],m1[3]);
			// printf("m2 : %x %x %x %x \n",m2[0],m2[1],m2[2],m2[3]);
			hashmap_free(map); // free memory
			return get_cs48_dm_fp(m2);
    	}
		--a;
	}
	printf("Failed! \n");
	hashmap_free(map);
	return 0;
	
}
/*
 * Test for find_exp_mess
 */
int test_exp(){
	uint32_t m1[4] = {0};
	uint32_t m2[4] = {0};
	find_exp_mess(m1,m2);

	// uint32_t m1[4] = {0xb0bf6a, 0x334662, 0xfd063a, 0xf8767a}; // point fixe
	// uint32_t m2[4] = {0x2fe609, 0xfb2832, 0x2d7986, 0x153887}; // hash ordinaire
	// m1 : 304bf0 e4858c d2220a d9dd42 
	// m2 : 3dd74e 9595fe 9dec42 97703c 

	printf("m2 : %x %x %x %x fp = %lx \n",m2[0],m2[1],m2[2],m2[3],get_cs48_dm_fp(m2));
	printf("m1 : %x %x %x %x hs = %lx \n",m1[0],m1[1],m1[2],m1[3],cs48_dm(m1,IV));

}
/*
 * hash function used in the map I used in full attack() function, in this case index is useless
 */
uint64_t msg_hash_attack(const void *item, uint64_t seed0, uint64_t seed1,int index) {
	const uint32_t *m = item;// m is block word + the hash of the previous block word h_{i-1}
	uint64_t h_prev = m[5];
	h_prev = (h_prev <<24) | m[4]; // h_prev is created
	uint64_t h_next = 0;
	h_next = cs48_dm(m,h_prev); // in this case index does not have effect 
	return h_next;
}


/*
	This function is called by the hashmap_get to compare if two elemnt have the same hash 
	a : the word we want to check if it's in the map, ie cs48_dm(a,fp) == h_i
	b : the word from the map of mess
*/
int compare_msg_attack(const void *a, const void *b, void *udata){ 
	
	if(msg_hash_attack(a,0,0,0) == msg_hash_attack(b,0,0,0)){
		printf("FOUND! \n");
		return 0;
	}
	return 1;
}

void attack(void)
{
	// find a expandale message with fixed-point fp
	uint32_t m1[4] = {0}; 
	uint32_t m2[4] = {0};
	uint64_t fp  = find_exp_mess(m1,m2);// fixed-point
	// Print the expandale message
	printf("expandale message is found fixed-point = %lx \n", fp);
	printf("m1 : %x %x %x %x \n",m1[0],m1[1],m1[2],m1[3]);
	printf("m2 : %x %x %x %x \n",m2[0],m2[1],m2[2],m2[3]);

	//The 2nd pre-image message of mess
	uint32_t pre_img[1ULL<< 20];
	uint64_t h = IV;

	// this hash is an array of 6 words of 24 bits
	//The first 4 are for the Key and the 2 last are for the hash of the previous m_{i-1}
	struct hashmap *mess_hashes = hashmap_new(sizeof(uint32_t)*6, 0, 0, 0, 
                                     msg_hash_attack, compare_msg_attack, NULL, NULL); 
	// Fill the hash map with all message m_i and their hashes 
	for (int i = 0; i < (1 << 20); i+=4)
	{
		// the message
		uint32_t mess[6];
		mess[0] = 0;
		mess[1] = 0;
		mess[2] = 0;
		mess[3] = i;
		// its hash 
		mess[4] = h & 0xFFFFFF;
		mess[5] = h >>24;
		h = cs48_dm(mess,h); // the value of next h ie h_i
		hashmap_set(mess_hashes,mess);
	}
	printf("hash map is filled  %x\n", hashmap_count(mess_hashes));
	uint64_t a=  1ULL << 48;
	uint32_t m3[6] = {0,0,0,0,fp & 0xFFFFFF, fp >>24};
	uint32_t *cm = m3;
	while(a>0){
		generate_msg_hash(m3); // create a message
		cm = hashmap_get(mess_hashes,m3);// check if there is i s.t h_i == cs48_dm(m3,fp)
		if (cm) {
        	printf("the message m_i                  : %x %x %x %x \n",cm[0],cm[1],cm[2],cm[3]);
			printf("the message cm collide with  m_i : %x %x %x %x \n",m3[0],m3[1],m3[2],m3[3]);
			hashmap_free(mess_hashes);
			uint32_t collision_index  = cm[3];// the index of the block where we find collision
			// Let's create our message
			pre_img[0] = m1[0];
			pre_img[1] = m1[1];
			pre_img[2] = m1[2];
			pre_img[3] = m1[3];
			for(uint32_t i =4; i< collision_index; i+=4){
				pre_img[0+i] = m2[0];
				pre_img[1+i] = m2[1];
				pre_img[2+i] = m2[2];
				pre_img[3+i] = m2[3];
			}
			pre_img[0+collision_index] = m3[0];
			pre_img[1+collision_index] = m3[1];
			pre_img[2+collision_index] = m3[2];
			pre_img[3+collision_index] = m3[3];
			for(uint32_t i =collision_index+4; i<(1ULL<<20); i+=4){
				pre_img[0+i] = 0;
				pre_img[1+i] = 0;
				pre_img[2+i] = 0;
				pre_img[3+i] = i;
			}

			// compute it's hash with/without padding of pre-image message
			printf("hash pre image : %lx \n",hs48(pre_img,(1<<18),0,0));
			printf("hash pre image with pad : %lx \n",hs48(pre_img,(1<<18),1,0));
			printf("===================\n");

			// compute it's hash with/without padding of mess message
			for(uint32_t i = 0; i<(1ULL<<20); i+=4){
				pre_img[0+i] = 0;
				pre_img[1+i] = 0;
				pre_img[2+i] = 0;
				pre_img[3+i] = i;
			}
			printf("hash mess : %lx \n",hs48(pre_img,(1<<18),0,0));
			printf("hash mess with pad : %lx \n",hs48(pre_img,(1<<18),1,0));
			printf("===================\n");
			return ;
    	}
		--a;
	}
	printf("Faild \n");
	//search for M' s.t H(M') = h_i with 0<= i <=l
}


/*
 * This function compute the hash of mess message
 * I don't get the same hash as in TP sheet however I passed the previous tests.
 */
int test_attack()
{
	uint32_t pre_img[1ULL<< 20];
	for(int i = 0; i<(1ULL<<20); i+=4){
		pre_img[0+i] = 0;
		pre_img[1+i] = 0;
		pre_img[2+i] = 0;
		pre_img[3+i] = i;
	}
	printf("hash mess : %lx \n",hs48(pre_img,(1<<18),0,0));
	printf("hash mess with pad : %lx \n",hs48(pre_img,(1<<18),1,0));
	printf("===================\n");
}


int main()
{
	attack();
	// test_sp48();
	// test_sp48_inv();
	// test_cs48_dm();
	// test_cs48_dm_fp();	
	// test_exp();	
	// attack();
	// test_attack();	
	return 0;
}
