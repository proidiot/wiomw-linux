#include <config.h>
#include "exp_backoff.h"
#include <limits.h>
#include <stdlib.h>

unsigned int exp_backoff(unsigned int tries)
{
	unsigned int result = 0;

	if (tries != 0) {
		unsigned int eceil = 0;

		if (tries >= sizeof(unsigned int) * 8) {
			eceil = UINT_MAX;
		} else {
			eceil = 1 << tries;
		}

		result = random() % eceil;
	}

	return result;
}

unsigned int trunc_exp_backoff(unsigned int tries, unsigned int ceil)
{
	unsigned int result = 0;

	if (tries != 0) {
		unsigned int eceil = 0;

		if (tries >= sizeof(unsigned int) * 8) {
			eceil = UINT_MAX;
		} else {
			eceil = 1 << tries;
		}

		if (ceil < UINT_MAX && eceil > ceil + 1) {
			eceil = ceil + 1;
		}

		result = random() % eceil;
	}

	return result;
}

