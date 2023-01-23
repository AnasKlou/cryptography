#include <stdint.h>
#include <stdio.h>
#include "mul11585.h"
#include "hashmap.c"


static const num128 g = {.t = {4398046511104LL, 0}};
static const num128 one = {.t = {1, 0}};


/*
 * compute g to x usinf recurcive Fast exponentiation 
 */
num128 gexp(uint64_t x) {
    if (x == 0){
        return one;
    }
    num128 z = gexp(x/2);
    if (x %2 ==0){
        return mul11585(z, z);
    }
    else{
        return mul11585(g,mul11585(z, z));
    }
    
}

/*
 * compute the value obsulte of a-b
 */
uint64_t minus_abs(uint64_t a, uint64_t b){
    if(a>b){
        return a-b;
    }
    return b-a;
}


/*
 * This function take a number x in parameter and return
 * if it is distinguished or not
 */
int distinguisher(num128 x){
    // computing the modulos of x modulo 1<<26
    // mod(x,1<<26)== mod(x.t[0],1<<26)
    if (((x.t[0] ^(0x4000000)) & 0x3FFFFFF) == 0){
        return 1;
    }
    return 0;
}

/*
 * hashing function used by hashmaps
 */
uint64_t msg_hash(const void *item, uint64_t seed0, uint64_t seed1,int index) {
	const uint64_t *m = item;
	uint64_t h = 0;
	h = m[0]+m[1];
	return h;
}

/* 
 * Compare function used by hashmap to compare two elements
 */
int compare_msg(const void *a, const void *b, void *udata){
	const uint64_t *m_1 = a;
	const uint64_t *m_2 = b;

	if (m_1[0]==m_2[0] && m_1[1]==m_2[1]){
		return 0;
	}
	return 1;
}

/*
 * Compute discrete logarithm of a target using Kangaroo method
 */
uint64_t dlog64(num128 target){

    // create table of e_i s.
    uint64_t table_of_ei[32] = {0};
    for(int i =0;i<21;++i){
        table_of_ei[i]  =1ULL<<i;
    }
    for(int i =21;i<32;++i){
        table_of_ei[i]  =1ULL<<(i+4);
    }
    uint64_t j = 0; // Sj index

    // creating tame and wild hashmaps and initialize them
    struct hashmap *tame_kangoroo = hashmap_new(sizeof(uint64_t)*3, 0, 0, 0, 
                                     msg_hash, compare_msg, NULL, NULL);
    struct hashmap *wild_kangoroo = hashmap_new(sizeof(uint64_t)*3, 0, 0, 0, 
                                     msg_hash, compare_msg, NULL, NULL);
    num128 y_0 = target;
    uint64_t prev_c = 0;
    uint64_t y_i[3] = {y_0.t[0],y_0.t[1],prev_c};
    uint64_t prev_b = 1ULL<<32;// starting point
    num128 x_0 = gexp(prev_b);
    uint64_t x_i[3] = {x_0.t[0],x_0.t[1],prev_b};
    
    if(distinguisher(x_0)){
        hashmap_set(tame_kangoroo,x_i);
    }
    if(distinguisher(y_0)){
        hashmap_set(wild_kangoroo,y_i);
    }

    uint64_t *get_y_c;
    uint64_t *get_x_b;
    int no_collision = 1;

    while(no_collision ){

        // Get from wild
        // verify if there is (x_i,b_i) in wild_kangoroo map
        get_x_b = hashmap_get(wild_kangoroo,x_i);
        if(get_x_b){
            // compute the exponent of h
            printf("The exponent of target is %lu \n",minus_abs(get_x_b[2],x_i[2]));
            hashmap_free(wild_kangoroo);
            hashmap_free(tame_kangoroo);
            return minus_abs(get_x_b[2],x_i[2]);
        }

        // Try to get from Tame
        // verify if there is (x_i,b_i) in tame_kangoroo map
        get_y_c = hashmap_get(tame_kangoroo,y_i);
        if(get_y_c){
            printf("The exponent of target is %lu \n",minus_abs(get_y_c[2],y_i[2]));
            hashmap_free(tame_kangoroo);
            hashmap_free(wild_kangoroo);
            return minus_abs(get_y_c[2],y_i[2]);

        }

        // compute the index j s.t x_i in S_j 
        j = (x_0.s) & 0x1F; 
        // j = (x_0.s) >>123; //decommenter si vous voulez essayer la division nauve des sous-ensemble
        // compute b_(i+1) for next x_i
        prev_b = prev_b + table_of_ei[j] ; 
        x_0 = mul11585(x_0,gexp(table_of_ei[j])); // next x_i
        // x_0  = gexp(prev_b);
        x_i[0] = x_0.t[0];
        x_i[1] = x_0.t[1];
        x_i[2] = prev_b;

        if(distinguisher(x_0)){
            hashmap_set(tame_kangoroo,x_i);
        }

        // compute next y_i
        j = (y_0.s) & 0x1F;// compute the index j s.t y_j in S_j
        // j = (y_0.s) >> 123; // de meme decommenter pour une division nauve de G
        prev_c = prev_c + table_of_ei[j]; // compute c_(i+1) for next x_i
        y_0 = mul11585(gexp(table_of_ei[j]),y_0); // computing next value of y_i as num128 

        // insert this value in hashmap
        y_i[0] = y_0.t[0];
        y_i[1] = y_0.t[1];
        y_i[2] = prev_c;
        if(distinguisher(y_0)){
            hashmap_set(wild_kangoroo,y_i);
        }
        
    }
}
int test_gexp(){
    uint64_t i = 257;
    uint64_t j = 112123123412345ULL;
    uint64_t n = 18014398509482143ULL;
    num128 res_i = gexp(i);
    num128 res_j = gexp(j);
    num128 res_n = mul11585(gexp(-1),g);
    print_num128(res_i);
    print_num128(res_j);
    print_num128(res_n);
    printf("res_i = %lX  %016lX \n",res_i.t[1],res_i.t[0]);
    printf("res_j = %lX  %016lX \n",res_j.t[1],res_j.t[0]);
    printf("res_n = %lX  %016lX \n",res_n.t[1],res_n.t[0]);
}

int test_dlog(){
    num128 target =  {.t = {0xB6263BF2908A7B09, 0x71AC72AF7B138ULL}} ; // gexp(247639217675125292ULL);
    // num128 target = {.t = { 0x0840EE23EECF13E4, 0x42F953471EDC0 }}; // gexp(257)
    printf("target = %lX%016lX \n",target.t[1],target.t[0]);
    uint64_t exponent = dlog64(target);
    num128 result = gexp(exponent);
    if(target.t[0]==result.t[0] && target.t[1]==result.t[1] ){
        printf("Passed!\n");
    }
    else{
        printf("Failed!\n");
    }
    return 0;
    /* some exponents ant time
     * 257                4mn24s
     * 247639317675155292 4mn
     * 247639217675125292 2mn 
     * 249635117600155882 4mn15s
     * 381635117671305882 24mn  
    */
    
}

int main(){
    // test_gexp();
    test_dlog();
}