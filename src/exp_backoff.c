/**
 * Copyright 2013, 2014 Who Is On My WiFi.
 *
 * This file is part of Who Is On My WiFi Linux.
 *
 * Who Is On My WiFi Linux is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Who Is On My WiFi Linux is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Who Is On My WiFi Linux.  If not, see <http://www.gnu.org/licenses/>.
 *
 * More information about Who Is On My WiFi Linux can be found at
 * <http://www.whoisonmywifi.com/>.
 */

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

