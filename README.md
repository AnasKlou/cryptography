## cryptography
## TP2 
#### Q.1/

In this qyestion I adopt hash map structure because it's has $O(1)\times hashing\_Cost $ in settig a new element and $O(1) \times 2\times hashing\_Cost $ to check and return it if it exist.

I created a hashmap contains $2^{24}$ random message, So given a random message the probability that this message willl not be in hashmap is $1-\frac{1}{2^{24}}$ so in average I will need to create  $3\times 2^{24}$ to find a expandale message in hash map.

So the complexity of this function is :
* $O(1)\times hashing\_Cost \times 2^{26}$ operations
* $O(1)\times 2^{24}$ in memory

In this question we did not use the same hashing function for setting and getting in order to profit the maximumfrom the implementation of hashmap.c

#### Q.2/

In average the probability to find an element `cm` such that there is `i` <u> h_i == cs48_dm(m3,fp)</u> is $1-\frac{1}{2^{30}}$ so in average we will need $3\times 2^{30}$ draws. This is true in the case that the generator of numbers is random an uniform.

The complexity of attack() function is :

$C = exp\_mess\_complexity +3\times 2^{30}\times hashing\_Cost$ 

For more details about the code look at attack() function in second_preim_48_file.c file

-------------------------------

## TP3

### Testing 

> to compile use : gcc -O3 -march=native logarithm.c -o test_dlog

> you already have an executable called dlog.

> there two test test_gexp for gexp function and test_dlog dlog function
------
## Cost 
* if we use algorithme like `Big step little step` it will cost $O(2\times\sqrt(N))$ in memory and in number of operation it cost $O(2\times\log(N)\times\sqrt(N))$ multiplications. 

* For a generic logarithm where we compute all possible values of $g^i$ and every time time we check with the target. In average it cots $O(\log(N)\times N)$ multiplications. 
--------
### Parameterisation :

As we want to compute our logarithms in $\mathbb{G}$ so : 
* $W = 2^{64}$ 
* $\mu = 2^{31}$
* $d = {2^{-26}}$
* $ k = 32$

Look for the values of ${e_1...e_k}$
* for all i =1..21 : $e_i = 2^{i-1}$
* for all i =22..k : $e_i = 2^{i+3}$
> I choose $e_i$ like that on order to be able to write any number as a sum of e_i the fatest way and also the mean of $e_i$ still $\mu$. 


for the subsets I decide to devide $\mathbb{G}$ to small $\mathbb{S_j}$ such that : 
$$x\in S_j \iff x=j[32]$$

I take them like that in order to homogenize the subsets. In this constructios of subsets I tried to make them uniform  

distinguisher is define as follows :
$$D(x) = 1  \iff  x = 0[2^{26}] $$

------
### Implementation :
In my code I chose the parametre as I mentionned before. For the starting point I choose $b_0 = 2^{32}$ and I used hashmap of arrays of `uint64_t` because it facilitate setting and getting elements. This implementation does not have a constant computing time for all values. sometimes it take less than 4min and sometime more than 20min to compute a disceret logarithmes.

The distinguisher is used in this implementation te reduce memory consumption.

### Modify some parametres :
-------------
### <u>Starting points</u>
* given start point $2^{32}$, the `dlog` of 
    * __0x71AC72AF7B138B6263BF2908A7B09__ is done within 2min 8sec in PC i53.4GHz
    * __0x164F4C386E74415A6856BF0E1646D__ is computed within 4min 
    * __0x471A0FF01378A36B98B5F22DC4FD7__ : 4min

* given start point $b_0 =2^{63} = \frac{W}{2}$, the `dlog` of 
    * __0x71AC72AF7B138B6263BF2908A7B09__ is done within 30min
    * __0x164F4C386E74415A6856BF0E1646D__ is computed within 23min
    * __0x471A0FF01378A36B98B5F22DC4FD7__ more than 30min
* $b_0 = 1$ has approximately the same perfomance as $b_0=2^{32}$ but $b_0=2^{32}$ still a little better.

> dlog(0x71AC72AF7B138B6263BF2908A7B09) = 247639217675125292ULL
-----------
### <u>Construnction of Subsets</u>
$S_j = \mathbb{[2^{123}\times(j-1),(2^{123}\times j)-1]}$ 
In this construnction $S_j$ are not homogenize ie $S_0$ it's the only subset contain small numbers.
During the computation of `dlog(0x71AC72AF7B138B6263BF2908A7B09)` I observ that the majority of intermediate values ($x_i, y_i$) are in $S_0$. In This case the algorithme is worst than generic attack because the length of steps is always 1 and moreover we stocks all previous values even they are not usefull.
