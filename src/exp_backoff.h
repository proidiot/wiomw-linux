#ifndef _WIOMW_EXP_BACKOFF_H_
#define _WIOMW_EXP_BACKOFF_H_

unsigned int exp_backoff(unsigned int tries);

unsigned int trunc_exp_backoff(unsigned int tries, unsigned int ceil);

#endif
