#ifndef __BLOOMFILTER_H
#define __BLOOMFILTER_H

#include <stdint.h>

struct bloomfilter {
	uint32_t nr_items;   // max number of items
	uint32_t nr_bits;    // number of bits
	uint32_t nr_hashs;   // number of hash functions
	double   prob;       // probability of false positives

	uint32_t hash_seed; // murmurhash seeds
	uint32_t nr_adds;    // number of added items, should not exceed nr_items

	uint64_t *hash_vals;
	uint8_t  bits[0];
};

struct bloomfilter *bf_init(uint32_t nr_items, double prob, uint32_t seed);
void bf_free(struct bloomfilter *bf);

void bf_add(struct bloomfilter *bf, const void *item, int len);
int bf_test(struct bloomfilter *bf, const void *item, int len);
// TODO
// void bf_remove(struct bloomfilter *bf, const void *item, int len);

#endif // __BLOOMFILTER_H
