#ifndef __MSGSTRUCT_H__
#define __MSGSTRUCT_H__
#define CTL_START 1
#define CTL_CHANGE 2
#define CTL_EXIT 3
#define ORIGIN_SIZE 65
#define ID_SIZE 64
#define SESS_SIZE 33
#define DESC_SIZE 256
#include "gamestruct.h"
struct MSG{
	long mtype;
	int sockfd;
	unsigned long type;
	char origin[ORIGIN_SIZE];
	char payload[2048];
};
struct MSG_LOGIN{
	char id[64];
	char pw[64];
};
struct MSG_ROOMS{
	char sessid[SESS_SIZE];
};
struct MSG_CREATE{
	char sessid[SESS_SIZE];
	char roomname[64];
};
struct MSG_JOIN{
	char sessid[SESS_SIZE];
	int room_idx;
};
struct MSG_CTL{
	char sessid[SESS_SIZE];
	int CONTROL_MSG;
	int CONTROL_ARG;
};
struct MSG_GDATA{
	char sessid[SESS_SIZE];
	int GDATA_SCORE;
	int GDATA_STATUS;	
};
struct MSG_RESULT{
	char sessid[SESS_SIZE];
};
struct MSG_STATUS{
	char sessid[SESS_SIZE];
};
struct RESP_LOGIN{
	int code;
	char sessid[SESS_SIZE];
	char description[DESC_SIZE];
};
struct RESP_REGISTER{
	int code;
	char description[DESC_SIZE];
};
struct RESP_ROOMS{
	int code;
	char description[DESC_SIZE];
	struct GAMEROOM rooms[16];
};
struct RESP_CREATE{
	int code;
	char description[DESC_SIZE];
	int room_idx;
};
struct RESP_JOIN{
	int code;
	char description[DESC_SIZE];
};
struct RESP_CTL{
	int code;
	char description[DESC_SIZE];
};
struct RESP_GDATA{
	int code;
	char description[DESC_SIZE];
	struct GAMEROOM room_info;
};
struct RESP_RESULT{
	int code;
	char description[DESC_SIZE];
	struct GAMEROOM room_info;
};
struct RESP_STATUS{
	int code;
	char description[DESC_SIZE];
	struct GAMEROOM room_info;
};
#endif
