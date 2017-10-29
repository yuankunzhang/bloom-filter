/**
 * Implementation of Bloom Filter.
 *
 * A Bloom Filter is fundamentally a bit set of m bits, that is
 * used to test whether an element is a member. False positive
 * matches are possible, however needs to be limited within a
 * small probability.
 */

#include <math.h>
#include <stdlib.h>

#include "bloomfilter.h"

// Little-endian only.
#define BITSET(bf, n) ( (bf)->bits[(n)/8] |= (1 << ((n)%8)) )
#define BITTEST(bf, n) ( (bf)->bits[(n)/8] & (1 << ((n)%8)) )

// Calculate m and k.
// See https://hur.st/bloomfilter
static void calc_params(uint32_t n, double p, uint32_t *pm, uint32_t *pk);

static uint64_t murmurhash(const void *key, int len, uint32_t seed);
static void bf_hash(struct bloomfilter *bf, const void *key, int len);


struct bloomfilter *bf_init(uint32_t nr_items, double prob, uint32_t seed)
{
	struct bloomfilter *bf;
	uint32_t m, k;

	if (nr_items == 0 || prob <= 0 || prob >= 1)
		return NULL;

	calc_params(nr_items, prob, &m, &k);

	bf = calloc(sizeof(*bf) + m, 1);
	if (bf == NULL)
		return NULL;

	bf->nr_items  = nr_items;
	bf->nr_bits   = m;
	bf->nr_hashs  = k;
	bf->prob      = prob;
	bf->hash_seed = seed;
	bf->nr_adds   = 0;

	bf->hash_vals = malloc(sizeof(uint64_t) * k);
	if (bf->hash_vals == NULL) {
		free(bf);
		return NULL;
	}

	return bf;
}

void bf_free(struct bloomfilter *bf)
{
	if (bf != NULL) {
		if (bf->hash_vals != NULL)
			free(bf->hash_vals);
		free(bf);
	}
}

void bf_add(struct bloomfilter *bf, const void *item, int len)
{
	bf_hash(bf, item, len);
	for (int i = 0; i < bf->nr_hashs; i++) {
		BITSET(bf, bf->hash_vals[i]);
	}

	bf->nr_adds += 1;
}

int bf_test(struct bloomfilter *bf, const void *item, int len)
{
	bf_hash(bf, item, len);
	for (int i = 0; i < bf->nr_hashs; i++) {
		if (!BITTEST(bf, bf->hash_vals[i]))
			return 0;
	}

	return 1;
}

void calc_params(uint32_t n, double p, uint32_t *pm, uint32_t *pk)
{
	// ln(2)
	const static double log2 = 0.693147180;
	// factor = ln(2) * ln(1/2)
	const static double factor = -2.081368981;

	*pm = (uint32_t) ceil(n * log(p) * factor);
	*pk = (uint32_t) ceil((*pm / n * log2));
}

// See https://sites.google.com/site/murmurhash/
uint64_t murmurhash(const void *key, int len, uint32_t seed)
{
	const uint64_t m = 0xc6a4a7935bd1e995;
	const int r = 47;

	uint64_t h = seed ^ (len * m);

	const uint64_t * data = (const uint64_t *)key;
	const uint64_t * end = data + (len/8);

	while(data != end) {
		uint64_t k = *data++;

		k *= m;
		k ^= k >> r;
		k *= m;

		h ^= k;
		h *= m;
	}

	const unsigned char * data2 = (const unsigned char*)data;

	switch(len & 7) {
	case 7: h ^= (uint64_t)(data2[6]) << 48;
	case 6: h ^= (uint64_t)(data2[5]) << 40;
	case 5: h ^= (uint64_t)(data2[4]) << 32;
	case 4: h ^= (uint64_t)(data2[3]) << 24;
	case 3: h ^= (uint64_t)(data2[2]) << 16;
	case 2: h ^= (uint64_t)(data2[1]) << 8;
	case 1: h ^= (uint64_t)(data2[0]);
	        h *= m;
	};

	h ^= h >> r;
	h *= m;
	h ^= h >> r;

	return h;
}

// Double hash: h(i, k) = (h1(k) + i * h2(k)) % m
// See https://en.wikipedia.org/wiki/Double_hashing?oldformat=true
void bf_hash(struct bloomfilter *bf, const void *key, int len)
{
	uint32_t seed1 = bf->hash_seed;
	uint32_t seed2 = 0 ^ seed1;

	uint64_t hash1 = murmurhash(key, len, seed1);
	uint64_t hash2 = murmurhash(key, len, seed2);

	for (int i = 0; i < bf->nr_hashs; i++) {
		bf->hash_vals[i] = (hash1 + i * hash2) % bf->nr_bits;
	}
}
