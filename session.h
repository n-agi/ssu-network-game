#include "uthash.h"
#include <time.h>
#define USER_IDLE 0
#define USER_PLAY 1
struct SESSION{
	char sessid[33];
	int idx;
	char id[64];
	time_t lastreq;
	int USER_STATUS;
	UT_hash_handle hh;
};

