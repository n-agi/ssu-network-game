#ifndef __GAMESTRUCT_H__
#define __GAMESTRUCT_H__
#define GAMEMAX 16
#define GR_UNUSED 0
#define GR_IDLE 1
#define GR_PLAY 2
#define GR_RESULT 3
struct GAMEROOM{
	int song;
	int owner;
	char roomname[64];
	int player[4];
	char player_id[4][64];
	int score[4];
	int PLAYER_STATUS[4];
	int GR_STATUS;
};
#endif
