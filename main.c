// ubuntu 14-04 64bit
// gcc-4.xx
// sudo apt-get install libjson0 libjson0-dev openssl-dev sqlite3-dev
// gcc -o game_server [objects].o -lsqlite3 -lcrypto -ljson
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ipc.h> 
#include <sys/msg.h> 
#include <sys/stat.h> 
#include <sqlite3.h>
#include <openssl/md5.h>
#include <json/json.h>

#include "msgstruct.h"
#include "gamestruct.h"
#include "session.h"

#define CONNMAX 1000
#define BYTES 1024
#define KEY_CTOH 1337
#define KEY_HTOR 1338

#define LOG_NORMAL 0
#define LOG_DEBUG 1

#ifndef LINE_MAX
#define LINE_MAX 1024
#endif
sqlite3 *db;
key_t host_key;
int listenfd, clients[CONNMAX];
int glob_fd;
char *login_query = "select * from user where id = ? and pw = ?";
char *id_query = "select * from user where id = ?";
char *insert_user_query = "insert into user(id,pw) values(?, ?)";
char *init = "create table if not exists user(idx INTEGER PRIMARY KEY,id varchar(64),pw varchar(32))";
bool init_flag = false;
struct SESSION *sessions = NULL;
struct GAMEROOM rooms[GAMEMAX];

char *encode(unsigned char hashed[]);
char *gen_rand32();
void handle();
void startServer(char *);
void respond(int);
void checkResp();
void init_gameroom();
int get_id_by_session(char *sessval);
int get_idx_available();
char *get_name_by_session(char *sessval);
char *get_name_by_idx(int idx);
void session_check();
void _log(int level, char *buf);

int main(int argc, char* argv[])
{
	pid_t child = 0;
	struct sockaddr_in clientaddr;
	socklen_t addrlen;
	char c;    
	int rc = 0;
	//Default Values PORT=9090
	char PORT[6];
	strcpy(PORT,"9090");
	char tmpbuf[LINE_MAX];
	int slot=0;
	//Parsing the command line arguments
	while ((c = getopt (argc, argv, "p:")) != -1)
		switch (c)
		{
			case 'p':
				strcpy(PORT,optarg);
				break;
			case '?':
				fprintf(stderr,"Wrong arguments given\n");
				exit(1);
			default:
				exit(1);
		}
	rc = sqlite3_open("data.db", &db);
	if(rc != SQLITE_OK){
		printf("error on sqlite3: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return 0;
	}
	snprintf(tmpbuf, LINE_MAX, "Server started at port no. %s\n", PORT);
	printf("%s", tmpbuf);
	_log(LOG_NORMAL, tmpbuf);
	//if messague queue exists, delete first	
	key_t tmp = msgget((key_t) KEY_HTOR, 0666);
	if(tmp != -1)
		msgctl(tmp,IPC_RMID, NULL);
	tmp = msgget((key_t) KEY_HTOR, 0666);
	if(tmp != -1)
		msgctl(tmp, IPC_RMID, NULL);
	//create message queue
	host_key = msgget((key_t) KEY_HTOR, IPC_CREAT|0666);
	tmp = msgget((key_t) KEY_CTOH, IPC_CREAT|0666);
	//initialize gameroom buffer to all nulls
	init_gameroom();
	//handler fork()
	child = fork();
	if(child == -1){
		perror("Error on fork handler");
		exit(1);
	}
	else if(child == 0){
		handle();
		exit(0);
	}
	else{
		int i;
		//initailize all clients to -1
		for (i=0; i<CONNMAX; i++)
			clients[i]=-1;
		//start Server
		startServer(PORT);

		// ACCEPT connections
		while (1)
		{
			//parent receives KEY_HTOR message queue.
			checkResp();
			//accept
			addrlen = sizeof(clientaddr);
			clients[slot] = accept (listenfd, (struct sockaddr *) &clientaddr, &addrlen);
			//no space available
			if(clients[slot] == -1) continue;
			bzero(tmpbuf, LINE_MAX);
			snprintf(tmpbuf, LINE_MAX, "Accept new client at fd %d, slot %d", clients[slot], slot);
			_log(LOG_NORMAL, tmpbuf);
			//accept failed
			if (clients[slot]<0)
				perror ("accept() error");
			else
			{
				//accept
				child = fork();
				if(child == 0){
					respond(slot);
					exit(0);
				}
				else if(child == -1){
					perror("Error on fork");
					exit(0);
				}
			}
			//finds empty space
			while (clients[slot]!=-1) slot = (slot+1)%CONNMAX;
		}
	}
	return 0;
}

//start server
void startServer(char *port)
{
	char tmpbuf[LINE_MAX];
	struct addrinfo hints, *res, *p;
	int enable = 1;
	// getaddrinfo for host
	memset (&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if (getaddrinfo( NULL, port, &hints, &res) != 0)
	{
		perror ("getaddrinfo() error");
		exit(1);
	}
	// socket and bind
	for (p = res ; p!=NULL; p=p->ai_next)
	{
		listenfd = socket (p->ai_family, p->ai_socktype, 0);
		if (listenfd == -1) continue;
		//SO_REUSEADDR
		if (setsockopt(listenfd,SOL_SOCKET, SO_REUSEADDR,  &enable, sizeof(int)) < 0){
			perror("failed to setsockopt");
			exit(1);
		}
		//Set socket to nonblock mode
		if( fcntl(listenfd, F_SETFL, O_NONBLOCK) == -1){
			perror("error on switching listen to non-block mode");
			exit(1);
		}
		//bind
		if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0) break;
	}
	if (p==NULL)
	{
		perror ("socket() or bind()");
		exit(1);
	}

	freeaddrinfo(res);

	// listen for incoming connections
	if ( listen (listenfd, 1000000) != 0 )
	{
		perror("listen() error");
		exit(1);
	}
	glob_fd = listenfd;
	snprintf(tmpbuf,LINE_MAX, "startServer() successfully finished!");
	_log(LOG_NORMAL, tmpbuf);
}

//client connection
void respond(int n)
{
	char tmpbuf[LINE_MAX];
	key_t key_id,key_id2;
	//open two message queues
	key_id = msgget(KEY_CTOH, IPC_EXCL | 0644);
	if(key_id < 0){
		perror("msgget at child->host error");
		exit(1);
	}
	key_id2 = msgget(KEY_HTOR, IPC_EXCL | 0644);
	if(key_id < 0){
		perror("msgget at host->child error");
		exit(1);
	}
	char mesg[99999], *reqline[3], data_to_send[BYTES], path[99999];
	char *postdata = NULL;
	char *tmp = NULL;
	char *post_key = NULL;
	char *post_data = NULL;
	char *origin = NULL;
	int rcvd, fd, bytes_read;

	bzero(mesg,sizeof(mesg));

	rcvd=recv(clients[n], mesg, 99999, 0);

	if (rcvd<0)    // receive error
		fprintf(stderr,("recv() error\n"));
	else if (rcvd==0)    // receive socket closed
	{
		fprintf(stderr,"Client disconnected upexpectedly.\n");
		exit(0);	
	}
	else    // message received
	{
		//reqline[0] = POST
		//reqline[1] = URL
		//reqline[2] = HTTP Version
		//afterwards : headers, Data
		//Fetchable header: COOKIE, ORIGIN
		reqline[0] = strtok(mesg, " \t\n");
		if(strncmp(reqline[0], "POST\x00",4) == 0 ){
			char *cookie = NULL;
			snprintf(tmpbuf, LINE_MAX, "POST request came.");
			_log(LOG_DEBUG, tmpbuf);	
			reqline[1] = strtok(NULL, " \t\n");
			reqline[2] = strtok(NULL, " \t\n");

			//log METHOD, URL
			snprintf(tmpbuf,LINE_MAX,"[DEBUG] reqline[0]: %s\n",reqline[0]);
			_log(LOG_DEBUG, tmpbuf);
			snprintf(tmpbuf,LINE_MAX,"[DEBUG] reqline[1]: %s",reqline[1]);
			_log(LOG_DEBUG, tmpbuf);
			tmp = reqline[2];
			while(strlen(tmp) > 1){
				//Cookie found?
				if(strncmp(tmp, "Cookie: ", 8) == 0){
					cookie = tmp + 8;
					//Does Cookie has value of session=[RANDVAL] ?
					if(strncmp(cookie, "session=", 8) == 0){
						cookie = cookie+8;
						bzero(tmpbuf, LINE_MAX);
						snprintf(tmpbuf, LINE_MAX, "Cookie: %s", cookie);
						_log(LOG_DEBUG, tmpbuf);
					}
					else
						cookie = NULL;
				}
				//Origin found?
				else if(strncmp(tmp, "Origin: ", 8) == 0){
					origin = tmp + 8;
					bzero(tmpbuf, LINE_MAX);
					snprintf(tmpbuf, LINE_MAX, "Origin: %s", origin);
					_log(LOG_DEBUG, tmpbuf);
				}
				tmp = strtok(NULL,"\n");
			}
			//skip 1 empty line
			tmp = strtok(NULL,"\n");
			postdata = strtok(tmp,"\n");
			//start position of postdata
			snprintf(tmpbuf, LINE_MAX, "POST data : %s\n", postdata);
			_log(LOG_DEBUG, tmpbuf);
			//Version is different, HTTP/1.0 or HTTP/1.1
			if( strncmp(reqline[2], "HTTP/1.0", 8) != 0 && strncmp(reqline[2], "HTTP/1.1", 8) != 0){
				snprintf(tmpbuf, LINE_MAX, "Unknown HTTP Version Requested");
				_log(LOG_DEBUG, tmpbuf);
				write(clients[n], "HTTP/1.1 400 Bad Request\n", 25);
			}
			//version correct
			else{
				// /login/
				if(strncmp(reqline[1], "/login\x00", 7) == 0 || strncmp(reqline[1], "/login/\x00",8) == 0){
					bool available[2];
					char id_buf[64];
					char pw_buf[64];
					bzero((char *)available, 2);
					post_key = strtok(postdata,"&");
					//post_key=post_data
					while(post_key != NULL){
						post_data = strchr(post_key, '=');
						if(post_data){
							*post_data = 0x00;
							post_data++;
						}
						if(strncmp(post_key,"id\x00",3) == 0){
							bzero(id_buf, sizeof(id_buf));
							strncpy(id_buf, post_data,64);
							available[0] = true;
						}	
						else if(strncmp(post_key,"pw\x00",3) == 0){
							bzero(pw_buf, sizeof(pw_buf));
							strncpy(pw_buf, post_data,64);
							available[1] = true;
						}
						post_key = strtok(NULL,"&");
					}
					//id=??&pw=?? exists
					if(available[0] && available[1]){
						struct MSG q_msg;
						struct MSG_LOGIN login_buf;
						bzero((char *)&q_msg, sizeof(q_msg));
						bzero((char *)&login_buf, sizeof(login_buf));
						q_msg.mtype = 1;
						q_msg.type = 1;
						q_msg.sockfd = clients[n];
						strncpy(q_msg.origin, origin, ORIGIN_SIZE - 1);
						strncpy(login_buf.id, id_buf, 64);
						strncpy(login_buf.pw, pw_buf, 64);
						memcpy(q_msg.payload, &login_buf, sizeof(struct MSG_LOGIN));
						if(msgsnd(key_id, (void *)&q_msg, sizeof(struct MSG)-sizeof(long), 0) == -1){
							perror("failed to push login message queue");
							exit(1);
						}
					}
				}
				// /register/
				else if(strncmp(reqline[1], "/register\x00", 10) == 0 || strncmp(reqline[1], "/register/\x00", 11) == 0){
					bool available[2];
					char id_buf[64];
					char pw_buf[64];
					post_key = strtok(postdata, "&");
					while(post_key != NULL){
						post_data = strchr(post_key, '=');
						if(post_data){
							*post_data = 0x00;
							post_data++;
						}
						if(strncmp(post_key, "id\x00", 3) == 0){
							bzero(id_buf, sizeof(id_buf));
							strncpy(id_buf, post_data, 64);
							available[0] = true;
						}
						else if(strncmp(post_key,"pw\x00", 3) == 0){
							bzero(pw_buf, sizeof(pw_buf));
							strncpy(pw_buf, post_data, 64);
							available[1] = true;
						}
						post_key = strtok(NULL, "&");
					}
					//id, pw exists
					if(available[0] && available[1]){
						struct MSG q_msg;
						struct MSG_LOGIN login_buf;
						bzero((char *)&q_msg, sizeof(struct MSG));
						bzero((char *)&login_buf, sizeof(struct MSG_LOGIN));
						q_msg.mtype = 1;
						q_msg.type = 2;
						q_msg.sockfd = clients[n];
						strncpy(q_msg.origin, origin, ORIGIN_SIZE - 1);
						strncpy(login_buf.id, id_buf, 64);
						strncpy(login_buf.pw, pw_buf, 64);
						memcpy(q_msg.payload, &login_buf, sizeof(struct MSG_LOGIN));
						if(msgsnd(key_id, (void *)&q_msg, sizeof(struct MSG)-sizeof(long), 0) == -1){
							perror("failed to push register message to queue");
							exit(1);
						}
					}
				}
				// /rooms/
				else if(strncmp(reqline[1], "/rooms\x00", 7) == 0 || strncmp(reqline[1], "/rooms/\x00", 8) == 0){
					struct MSG q_msg;
					struct MSG_ROOMS msg;
					bzero((char *)&q_msg, sizeof(struct MSG));
					bzero((char *)&msg, sizeof(struct MSG_ROOMS));
					q_msg.mtype = 1;
					q_msg.type = 3;
					q_msg.sockfd = clients[n];
					strncpy(q_msg.origin, origin, ORIGIN_SIZE - 1);
					//q_msg.payload[0] = 0x01 If cookie does not exists, 0x00 if cookie exists
					if(cookie == NULL){
						q_msg.payload[0] = '\x01';
						if(msgsnd(key_id, (void *)&q_msg, sizeof(struct MSG)-sizeof(long), 0) == -1){
							perror("failed to push room message to queue");
							exit(1);
						}
					}
					else{
						q_msg.payload[0] = '\x00';
						strncpy(msg.sessid, cookie, 32);
						strncpy(&q_msg.payload[1], cookie, 32);
						if(msgsnd(key_id, (void *)&q_msg, sizeof(struct MSG)-sizeof(long), 0) == -1){
							perror("failed to push room message to queue");
							exit(1);
						}
					}
				}
				// /create/
				else if(strncmp(reqline[1], "/create\x00", 8) == 0 || strncmp(reqline[1], "/create/\x00", 9) == 0){
					struct MSG q_msg;
					struct MSG_CREATE msg;
					char *roomname = NULL;
					bzero((char *)&msg, sizeof(struct MSG_CREATE));
					bzero((char *)&q_msg, sizeof(struct MSG));
					q_msg.mtype = 1;
					q_msg.type = 4;
					q_msg.sockfd = clients[n];
					strncpy(q_msg.origin, origin, 32);
					post_key = strtok(postdata, "&");
					while(post_key != NULL){
						post_data = strchr(post_key, '=');
						if(post_data){
							*post_data = 0x00;
							post_data++;
						}
						snprintf(tmpbuf, LINE_MAX, "key: %s, data: %s\n",post_key, post_data);
						_log(LOG_DEBUG, tmpbuf);
						if(strncmp(post_key,"roomname\x00", 9) == 0){
							roomname = post_data; 
						}
						post_key = strtok(NULL, "&");
					}
					if(cookie == NULL){
						snprintf(tmpbuf, LINE_MAX, "Cookie is not set!");
						_log(LOG_DEBUG, tmpbuf);
						q_msg.payload[0] = '\x01';

						if(msgsnd(key_id, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
							perror("failed to push create message to queue");
							exit(1);
						}
					}
					else{
						q_msg.payload[0] = '\x00';
						if(roomname != NULL)
							strncpy(msg.roomname, roomname, 64);
						strncpy(msg.sessid, cookie, 32);
						memcpy(&q_msg.payload[1], &msg, sizeof(struct MSG_CREATE));
						if(msgsnd(key_id, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
							perror("failed to push create message to queue");
							exit(1);
						}
					}
				}
				else if(strncmp(reqline[1], "/join\x00", 6) == 0 || strncmp(reqline[1], "/join/\x00", 7) == 0){
					struct MSG q_msg;
					struct MSG_JOIN msg;
					int join_idx = -1;
					bzero((char *)&q_msg, sizeof(struct MSG));
					bzero((char *)&msg, sizeof(struct MSG_JOIN));
					q_msg.mtype = 1;
					q_msg.type = 5;
					q_msg.sockfd = clients[n];
					strncpy(q_msg.origin, origin, ORIGIN_SIZE - 1);
					post_key = strtok(postdata, "&");
					while(post_key != NULL){
						post_data = strchr(post_key, '=');
						if(post_data){
							*post_data = 0x00;
							post_data++;
						}
						if(strncmp(post_key, "idx\x00", 4) == 0){
							snprintf(tmpbuf, LINE_MAX, "join, idx found %s\n", post_data);
							_log(LOG_DEBUG, tmpbuf);
							join_idx = atoi(post_data);
						}
						post_key = strtok(NULL, "&");
					}
					if(cookie == NULL){
						snprintf(tmpbuf, LINE_MAX, "[DEBUG-join] Cookie is not set.\n");
						_log(LOG_DEBUG, tmpbuf);
						q_msg.payload[0] = '\x01';
						if(msgsnd(key_id, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
							perror("failed to push join message to queue");
							exit(1);
						}
					}
					else{
						q_msg.payload[0] = '\x00';
						msg.room_idx = join_idx;
						strncpy(msg.sessid, cookie, 32);
						memcpy(&q_msg.payload[1], &msg, sizeof(struct MSG_JOIN));
						if(msgsnd(key_id, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
							perror("failed to push join message to queue");
							exit(1);
						}
					}
				}
				else if(strncmp(reqline[1], "/control\x00", 9) == 0 || strncmp(reqline[1], "/control/\x00", 10) == 0){
					struct MSG q_msg;
					struct MSG_CTL msg;
					int command = 0;
					int command_arg = -1;
					bzero((char *)&q_msg, sizeof(struct MSG));
					bzero((char *)&msg, sizeof(struct MSG_JOIN));
					q_msg.mtype = 1;
					q_msg.type = 6;
					q_msg.sockfd = clients[n];
					strncpy(q_msg.origin, origin, 32);
					post_key = strtok(postdata, "&");
					while(post_key != NULL){
						post_data = strchr(post_key, '=');
						if(post_data){
							*post_data = 0x00;
							post_data++;
						}
						//cmd=[??]&arg=[??]
						if(strncmp(post_key, "cmd", 3) == 0){
							if(strncmp(post_data, "start", 5) == 0){
								command = CTL_START;
							}
							else if(strncmp(post_data, "exit", 4) == 0){
								command = CTL_EXIT;
							}
							else if(strncmp(post_data, "change", 6) == 0){
								command = CTL_CHANGE;
							}
						}
						else if(strncmp(post_key, "arg", 3) == 0){
							command_arg = atoi(post_data);
						}
						post_key = strtok(NULL, "&");
					}
					if(cookie == NULL){
						q_msg.payload[0] = '\x01';
						if(msgsnd(key_id, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
							exit(1);
						}
					}
					else{
						q_msg.payload[0] = '\x00';
						strncpy(msg.sessid, cookie, 32);
						msg.CONTROL_MSG = command;
						msg.CONTROL_ARG = command_arg;
						memcpy(&q_msg.payload[1], &msg, sizeof(struct MSG_CTL));
						if(msgsnd(key_id, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0 ) == -1){
							exit(1);
						}
					}
				}
				else if(strncmp(reqline[1], "/gdata\x00", 7) == 0 || strncmp(reqline[1], "/gdata/\x00", 8) == 0){
					struct MSG q_msg;
					struct MSG_GDATA msg;
					bzero((char *)&q_msg, sizeof(struct MSG));
					bzero((char *)&msg, sizeof(struct MSG_GDATA));
					q_msg.mtype = 1;
					q_msg.type = 7;
					q_msg.sockfd=  clients[n];
					strncpy(q_msg.origin, origin, 32);
					post_key = strtok(postdata, "&");
					int score = -1;
					int status = -1;
					//score=[??]&status=[??]
					while(post_key != NULL){
						post_data = strchr(post_key, '=');
						if(post_data){
							*post_data = 0x00;
							post_data++;
						}
						if(strncmp(post_key, "score", 5) == 0){
							score = atoi(post_data);		
						}
						else if(strncmp(post_key, "status", 6) == 0){
							status = atoi(post_data);
						}
						post_key = strtok(NULL, "&");
					}
					if(cookie == NULL){
						q_msg.payload[0] = '\x01';
						if(msgsnd(key_id, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
							exit(1);
						}
					}
					else{
						q_msg.payload[0] = '\x00';
						strncpy(msg.sessid, cookie, 32);
						msg.GDATA_SCORE = score;
						msg.GDATA_STATUS = status;
						memcpy(&q_msg.payload[1], &msg, sizeof(struct MSG_GDATA));
						if(msgsnd(key_id, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) ==-1){
							exit(1);
						}
					}
				}
				else if(strncmp(reqline[1], "/result\x00", 8) == 0 || strncmp(reqline[1], "/result/\x00", 9) == 0){
					struct MSG q_msg;
					struct MSG_RESULT msg;
					bzero((char *)&q_msg, sizeof(struct MSG));
					bzero((char *)&msg, sizeof(struct MSG_RESULT));
					q_msg.mtype = 1;
					q_msg.type = 8;
					q_msg.sockfd = clients[n];
					strncpy(q_msg.origin, origin, ORIGIN_SIZE - 1);
					if(cookie == NULL){
						q_msg.payload[0] = '\x01';
						if(msgsnd(key_id, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
							exit(1);
						}
					}else{
						q_msg.payload[0] = '\x00';
						strncpy(msg.sessid, cookie, SESS_SIZE - 1);
						memcpy(&q_msg.payload[1], &msg, sizeof(struct MSG_RESULT));
						if(msgsnd(key_id, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
							exit(1);
						}
					}	
				}
				else if(strncmp(reqline[1], "/status\x00", 8) == 0 || strncmp(reqline[1], "/status/\x00", 9) == 0){
					struct MSG q_msg;
					struct MSG_STATUS msg;
					bzero((char *)&q_msg, sizeof(struct MSG));
					bzero((char *)&msg, sizeof(struct MSG_STATUS));
					q_msg.mtype = 1;
					q_msg.type = 9;
					q_msg.sockfd = clients[n];
					strncpy(q_msg.origin, origin, ORIGIN_SIZE -1);
					if(cookie == NULL){
						q_msg.payload[0] = '\x01';
						memcpy(&q_msg.payload[1], &msg, sizeof(struct MSG_STATUS));
						if(msgsnd(key_id, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
							exit(1);
						}
					}
					else{
						q_msg.payload[0] = '\x00';
						strncpy(msg.sessid, cookie, SESS_SIZE - 1);
						memcpy(&q_msg.payload[1], &msg, sizeof(struct MSG_STATUS));
						if(msgsnd(key_id, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
							exit(1);
						}
					}
				}
				else{
					printf("[DEBUG] unknown url fetched\n");
					write(clients[n], "HTTP/1.1 404 Not Found\n\n", 24);
					shutdown (clients[n], SHUT_RDWR);         //All further send and recieve operations are disabled
					close(clients[n]);
					clients[n]=-1;
				}
			}
		}
		//returns Access-Control-Allow-Origins for Preflight OPTIONS packet
		else if(strncmp(reqline[0], "OPTIONS\x00",7) == 0 ){
			snprintf(tmpbuf, LINE_MAX, "OPTIONS method requested. Maybe flight from Browser at %s.", origin);
			_log(LOG_NORMAL, tmpbuf);	
			char tmp[2048];
			//end(msg.sockfd, "HTTP/1.1 200 OK\r\n", 16, 0);
			send(clients[n], "HTTP/1.1 200 OK\r\n", 16, 0);
			snprintf(tmp, 2048, "Access-Control-Allow-Origin: %s\r\n", origin);
			send(clients[n], "Access-Control-Allow-Methods: POST\r\n", 36, 0);
			send(clients[n], tmp, strlen(tmp)-1, 0);
			shutdown(clients[n], SHUT_RDWR);
			close(clients[n]);
			clients[n] = -1;
		}
		//No other method is available
		else{
			snprintf(tmpbuf, LINE_MAX, "Not allowed method has requested from %s.", origin);
			_log(LOG_NORMAL, tmpbuf);
			write(clients[n], "HTTP/1.1 405 Method Not Allowed\r\n", 34);
			shutdown (clients[n], SHUT_RDWR);
			close(clients[n]);
			clients[n]=-1;
		}
	}
	
	snprintf(tmpbuf, LINE_MAX, "End of socket handler");
	_log(LOG_DEBUG, tmpbuf);
	exit(0);
}

//Main loop of handler
void handle(){
	int rc;
	struct MSG msg;
	sqlite3_stmt *res;
	key_t key_id,key_id2;
	char *err = NULL;
	char tmpbuf[LINE_MAX];
	//opens message queue
	key_id = msgget((key_t)KEY_CTOH, IPC_EXCL|0666);
	if(key_id == -1){
		perror("msgget host to client error");
		exit(-1);
	}
	key_id2 = msgget((key_t)KEY_HTOR, IPC_EXCL|0666);
	if(key_id == -1){
		perror("msgget client to host error");
		return;
	}
	//sqlite3 table exists?
	if(!init_flag){
		
		snprintf(tmpbuf, LINE_MAX, "setting first query to create table..");
		_log(LOG_DEBUG, tmpbuf);
		rc = sqlite3_exec(db,init,0,0,&err);
		if(rc != SQLITE_OK){
			printf("failed to create first table : %s\n", err);
			sqlite3_free(err);
			return;
		}
		init_flag =true;
	}
	while(1){
		bzero(&msg, sizeof(struct MSG));
		if(msgrcv(key_id, (void *)&msg, sizeof(struct MSG) - sizeof(long), 0, IPC_NOWAIT) == -1){
			continue;
		}
		//login
		if(msg.type == 1){
			struct MSG q_msg;              
			struct RESP_LOGIN resp; 
			bzero((char *)&q_msg,sizeof(struct MSG));
			bzero((char *)&resp, sizeof(struct RESP_LOGIN));
			q_msg.mtype = 1;
			q_msg.type = 1;
			q_msg.sockfd = msg.sockfd;
			strncpy(q_msg.origin, msg.origin, ORIGIN_SIZE -1 );
			struct MSG_LOGIN *p = (struct MSG_LOGIN *)msg.payload;
			unsigned char hashed[MD5_DIGEST_LENGTH];
			char *encoded;	
			snprintf(tmpbuf, LINE_MAX,"fetched : id:%s, pw:%s", p->id, p->pw);
			_log(LOG_DEBUG, tmpbuf);
			MD5(p->pw,strlen(p->pw),hashed);
			encoded = encode(hashed);
			rc = sqlite3_prepare_v2(db,login_query,-1,&res, 0);
			if(rc == SQLITE_OK){
				//bind text
				sqlite3_bind_text(res,1,p->id,strlen(p->id), 0);
				sqlite3_bind_text(res,2,encoded,32,0);
			}
			else{
				snprintf(tmpbuf, LINE_MAX,"Failed to execute login query : %s\n",sqlite3_errmsg(db));
				_log(LOG_NORMAL, tmpbuf);
				sqlite3_finalize(res);
				free(encoded);
				encoded = NULL;
				continue;
			}
			int step = sqlite3_step(res);
			if(step == SQLITE_ROW){
				//login success
				const char *success_id = sqlite3_column_text(res,1);
				char *randval = gen_rand32();
				struct SESSION *check = NULL;
				bool already_login = false;
				for(check = sessions ; check != NULL ; check = check->hh.next){
					if(strncmp(check->id, success_id, strlen(check->id)) == 0){
						already_login = true;
						break;
					}
				}
				if(already_login){
					resp.code = 2;
					strncpy(resp.description, "Already Login-ed account!\x00", 26);
					memcpy(q_msg.payload, &resp, sizeof(struct RESP_LOGIN));
					if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
						perror("Error on sending handle->response");
						exit(1);
					}

				}
				else{
					//set SESSION struct first
					struct SESSION *s = (struct SESSION *)malloc(sizeof(struct SESSION));
					bzero((char *)s, sizeof(struct SESSION));
					strncpy(s->sessid,randval,32);
					s->idx = atoi(sqlite3_column_text(res,0));
					strncpy(s->id, success_id, strlen(success_id));
					s->USER_STATUS = USER_IDLE;
					HASH_ADD_STR(sessions,sessid,s);
					//return response
					resp.code = 0;
					strncpy(resp.sessid, randval, 32);
					strncpy(resp.description, "Login Success\x00", 15);
					memcpy(q_msg.payload, &resp, sizeof(struct RESP_LOGIN));
					if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
						perror("Error on sending handle->response");
						exit(1);
					}
				}
			}
			else{
				//not found at DB
				snprintf(tmpbuf, LINE_MAX, "cannot find user with id : %s, pw : %s\n", p->id, encoded);
				_log(LOG_DEBUG, tmpbuf);
				resp.code = 1;
				strncpy(resp.description, "Login Failed\x00",13);
				memcpy(q_msg.payload, &resp, sizeof(struct RESP_LOGIN));
				if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
					perror("Error on sending login fail handle -> response");
					exit(1);
				}
			}
			sqlite3_finalize(res);
			free(encoded);
			encoded = NULL;
		}
		//register
		else if(msg.type == 2){
			struct MSG_LOGIN *p = (struct MSG_LOGIN *)msg.payload;
			unsigned char hashed[MD5_DIGEST_LENGTH];
			char *encoded;
			snprintf(tmpbuf, LINE_MAX, "register fetched : id=%s, pw=%s\n",p->id, p->pw);
			_log(LOG_DEBUG, tmpbuf);
			MD5(p->pw, strlen(p->pw), hashed);
			encoded = encode(hashed);
			rc = sqlite3_prepare_v2(db, id_query, -1, &res, 0);
			if(rc == SQLITE_OK){
				sqlite3_bind_text(res,1,p->id, strlen(p->id), 0);
			}
			else{
				//Query build fail
				snprintf(tmpbuf, LINE_MAX,"Failed to search id : %s\n", sqlite3_errmsg(db));
				_log(LOG_DEBUG, tmpbuf);
				sqlite3_finalize(res);
				free(encoded);
				encoded = NULL;
				continue;
			}
			int step = sqlite3_step(res);
			if(step == SQLITE_ROW){
				//ID exists
				snprintf(tmpbuf, LINE_MAX, "Register query came but already exists id : %s\n", p->id);
				_log(LOG_DEBUG, tmpbuf);
				struct MSG q_msg;
				struct RESP_REGISTER resp;
				bzero((char *)&q_msg, sizeof(struct MSG));
				bzero((char *)&resp, sizeof(struct RESP_REGISTER));
				q_msg.mtype = 1;
				q_msg.type = 2;
				q_msg.sockfd = msg.sockfd;
				strncpy(q_msg.origin, msg.origin, ORIGIN_SIZE - 1);
				resp.code = 1;
				strncpy(resp.description, "ID already exists!\x00", 19);
				memcpy(q_msg.payload, &resp, sizeof(struct RESP_REGISTER));
				if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
					perror("Error on sending fail register handle->response");
					exit(0);
				}
				sqlite3_finalize(res);
				free(encoded);
				encoded=NULL;
			}
			else{
				//Register success
				sqlite3_finalize(res);
				rc = sqlite3_prepare_v2(db,insert_user_query, -1, &res, 0);
				if(rc == SQLITE_OK){
					sqlite3_bind_text(res,1,p->id,strlen(p->id), 0);
					sqlite3_bind_text(res,2,encoded,32,0);
				}
				else{
					printf("[DEBUG] failed to exec insert query : %s\n", sqlite3_errmsg(db));
					sqlite3_finalize(res);
					free(encoded);
					encoded=NULL;
					continue;
				}
				int step = sqlite3_step(res);
				//Commit DB
				sqlite3_finalize(res);
				struct MSG q_msg;
				struct RESP_REGISTER resp;
				bzero((char *)&q_msg, sizeof(struct MSG));
				bzero((char *)&resp, sizeof(struct RESP_REGISTER));
				q_msg.mtype = 1;
				q_msg.type = 2;
				q_msg.sockfd = msg.sockfd;
				strncpy(q_msg.origin, msg.origin, ORIGIN_SIZE-1);
				resp.code = 0;
				strncpy(resp.description, "Register Success\x00",16);
				memcpy(q_msg.payload, &resp,sizeof(struct RESP_REGISTER));
				if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
					perror("Error on sending success register handle->response");
					exit(0);
				}
			}
			free(encoded);
			encoded=NULL;
		}
		//rooms
		else if(msg.type == 3){
			struct MSG q_msg;
			struct RESP_ROOMS resp;
			bzero((char *)&q_msg, sizeof(struct MSG));
			bzero((char *)&resp, sizeof(struct RESP_ROOMS));
			q_msg.mtype = 1;
			q_msg.type = 3;
			q_msg.sockfd = msg.sockfd;
			strncpy(q_msg.origin, msg.origin, ORIGIN_SIZE - 1);
			if(msg.payload[0] == '\x01'){
				//session is not settled.
				snprintf(tmpbuf, LINE_MAX, "rooms: session is not settled.\n");
				_log(LOG_DEBUG, tmpbuf);
				resp.code = 1;
				strncpy(resp.description, "You are not logined.\x00",21);
				memcpy(q_msg.payload, &resp, sizeof(struct RESP_ROOMS));
				if(msgsnd(key_id2, (void *) &q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
					perror("Error on sending failed by session rooms handle->response");
					exit(0);
				}
			}
			else{
				int i = 0;
				char cookie[33];
				bzero(cookie, sizeof(cookie));
				strncpy(cookie,&msg.payload[1],32);
				struct SESSION *s = NULL;
				HASH_FIND_STR(sessions, cookie, s);
				if(s){
					//copy all room data to resp.rooms[i] <- rooms[i]
					for(i = 0 ; i < GAMEMAX ; i++){
						memcpy(&resp.rooms[i], &rooms[i],sizeof(struct GAMEROOM));
					}
					resp.code = 0;
					strncpy(resp.description, "Successfully fetched.\x00", 22);
					memcpy(q_msg.payload, &resp, sizeof(struct RESP_ROOMS));
					if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
						perror("Error on sending success room info handle->response");
						exit(0);
					}
				}
				else{
					//session does not exists
					resp.code = 2;
					strncpy(resp.description, "Your session is unknown or closed.\x00",34);
					memcpy(q_msg.payload, &resp, sizeof(struct RESP_ROOMS));
					if(msgsnd(key_id2, (void *) &q_msg, sizeof(struct MSG)- sizeof(long), 0) == -1){
						perror("Error on sending failed by unkonwn session rooms handle->response");
						exit(0);
					}
				}
			}
		}
		else if(msg.type == 4){
			struct MSG q_msg;
			struct RESP_CREATE resp;
			bzero((char *)&q_msg, sizeof(struct MSG));
			bzero((char *)&resp, sizeof(struct RESP_CREATE));
			q_msg.mtype = 1;
			q_msg.type = 4;
			q_msg.sockfd = msg.sockfd;
			strncpy(q_msg.origin, msg.origin, ORIGIN_SIZE - 1);
			if(msg.payload[0] == '\x01'){
				resp.code = 1;
				strncpy(resp.description, "You are not logined.\x00",21);
				memcpy(q_msg.payload, &resp, sizeof(struct RESP_ROOMS));
				if(msgsnd(key_id2, (void *) &q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
					perror("Error on sending failed by session rooms handle->response");
					exit(0);
				}	
			}
			else{
				struct MSG_CREATE *p = (struct MSG_CREATE *)&msg.payload[1];
				char cookie[33];
				struct SESSION *s = NULL;
				bzero(cookie, sizeof(cookie));
				strncpy(cookie, p->sessid, SESS_SIZE - 1);
				HASH_FIND_STR(sessions, cookie, s);
				if(s){
					int available_idx = -1;
					available_idx = get_idx_available();
					//no empty room
					if(available_idx == -1){
						resp.code = 1;
						strncpy(resp.description, "There is no room for new game room.\x00", 36);
						memcpy(q_msg.payload, &resp, sizeof(struct RESP_CREATE));
						if(msgsnd(key_id2, (void *) &q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
							perror("Error on sending failed by no more space create handle->response");
							exit(1);
						}
					}
					else{
						snprintf(tmpbuf, LINE_MAX, "create: Available idx : %d", available_idx);
						_log(LOG_DEBUG, tmpbuf);

						int my_idx = get_id_by_session(s->sessid);
						int status = get_status_by_session(s->sessid);
						if(status != USER_IDLE){
							//already playing game, cannot create room
							resp.code = 3;
							strncpy(resp.description, "You already own your room or playing!\x00", 38);
							memcpy(q_msg.payload, &resp, sizeof(struct RESP_CREATE));
							if(msgsnd(key_id2, (void *) &q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
								perror("Error on sending success create message handle->response");
								exit(1);
							}
						}
						else{
							//set rooms[available_idx].GR_STATUS = GR_IDLE
							//create room
							rooms[available_idx].GR_STATUS = GR_IDLE;
							strncpy(rooms[available_idx].roomname, p->roomname, 64);
							rooms[available_idx].player[0] = my_idx;
							rooms[available_idx].PLAYER_STATUS[0] = GR_IDLE;
							strncpy(rooms[available_idx].player_id[0], s->id, 64);
							rooms[available_idx].owner = my_idx;
							s->USER_STATUS = USER_PLAY;
							resp.code = 0;
							strncpy(resp.description, "Successfully created new game room.\x00", 36);
							resp.room_idx = available_idx;
							memcpy(q_msg.payload, &resp, sizeof(struct RESP_CREATE));
							if(msgsnd(key_id2, (void *) &q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
								perror("Error on sending success create message handle->response");
								exit(1);
							}
						}
					}
				}
				else{
					resp.code = 2;
					strncpy(resp.description, "Your session is unknown or closed.\x00", 34);
					memcpy(q_msg.payload, &resp, sizeof(struct RESP_CREATE));
					if(msgsnd(key_id2, (void *) &q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
						perror("Error on sending failed by unknown session create handle->response");
						exit(1);
					}
				}
			}
		}
		//join
		else if(msg.type == 5){
			struct MSG q_msg;
			struct RESP_JOIN resp;
			bzero((char *)&q_msg, sizeof(struct MSG));
			bzero((char *)&resp, sizeof(struct RESP_JOIN));
			q_msg.mtype = 1;
			q_msg.type = 5;
			q_msg.sockfd = msg.sockfd;
			strncpy(q_msg.origin, msg.origin, ORIGIN_SIZE - 1);
			if(msg.payload[0] == '\x01'){
				resp.code = 1;
				strncpy(resp.description, "You are not logined!\x00", 21);
				memcpy(q_msg.payload, &resp, sizeof(struct RESP_JOIN));
				if(msgsnd(key_id2, (void *) &q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
					perror("Error on sending failed by session message handle->response");
					exit(1);
				}
			}
			else if(msg.payload[0] == '\x00'){
				struct MSG_JOIN *p = (struct MSG_JOIN *)&msg.payload[1];
				struct SESSION *s = NULL;
				char cookie[33];
				int i = 0;
				bzero(cookie, sizeof(cookie));
				strncpy(cookie, p->sessid, SESS_SIZE - 1);
				HASH_FIND_STR(sessions,cookie, s);
				if(s){
					if(s->USER_STATUS != USER_IDLE){
						//already playing
						resp.code = 3;
						strncpy(resp.description, "You are already playing.\x00",25);
						memcpy(q_msg.payload, &resp, sizeof(struct RESP_JOIN));
						if(msgsnd(key_id2, (void *) &q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
							perror("Error on sending not idle status join handle->response");
							exit(1);
						}
					}
					else{
						bool can_join = false;
						bool is_playing = false;
						//POST data room_idx is invalid
						if(p->room_idx < 0 || p->room_idx > 15){
							resp.code = 6;
							strncpy(resp.description, "Room index is not correctly inputted.\x00",38);
							memcpy(q_msg.payload, &resp, sizeof(struct RESP_JOIN));
							if(msgsnd(key_id2, (void *) &q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
								perror("Error on sending room idx error join handle->response");
								exit(1);
							}
						}
						else{
							if(rooms[p->room_idx].GR_STATUS != GR_IDLE)
								is_playing = true;
							else
								is_playing = false;
							if(!is_playing){
								//find empty space and insert user info
								for(i = 0 ; i < 4 ; i++){					
									if(rooms[p->room_idx].player[i] == GR_UNUSED){
										rooms[p->room_idx].player[i] = get_id_by_session(p->sessid);
										strncpy(rooms[p->room_idx].player_id[i], s->id, 64);
										s->USER_STATUS = USER_PLAY;
										rooms[p->room_idx].PLAYER_STATUS[i] = GR_IDLE;
										can_join = true;
										break;
									}
								}
							}
							if(!is_playing){
								if(!can_join){
									//full
									resp.code = 4;
									strncpy(resp.description, "Room is already full.\x00", 22);
									memcpy(q_msg.payload, &resp, sizeof(struct RESP_JOIN));
									if(msgsnd(key_id2, (void *) &q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
										perror("Error on sending room full join handle->response");
										exit(1);
									}
								}
								else{
									resp.code = 0;
									strncpy(resp.description, "Successfully joined the room.\x00",30);
									memcpy(q_msg.payload, &resp, sizeof(struct RESP_JOIN));
									if(msgsnd(key_id2, (void *) &q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
										perror("Error on sending room join handle->response");
										exit(1);
									}
								}
							}
							else{
								resp.code = 5;
								strncpy(resp.description, "Selected room is already playing or unused.\x00",44);
								memcpy(q_msg.payload, &resp, sizeof(struct RESP_JOIN));
								if(msgsnd(key_id2, (void *) &q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
									perror("Error on sending room not idle join handle->response");
									exit(1);
								}
							}
						}
					}
				}
				else{
					resp.code = 2;
					strncpy(resp.description, "Your session is unknown or closed.\x00", 34);
					memcpy(q_msg.payload, &resp, sizeof(struct RESP_JOIN));
					if(msgsnd(key_id2, (void *) &q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
						perror("Error on sending failed by unknwon session join handle->response");
						exit(1);
					}
				}
			}
		}
		else if(msg.type == 6){
			struct MSG q_msg;
			struct RESP_CTL resp;
			bzero((char *)&q_msg, sizeof(struct MSG));
			bzero((char *)&resp, sizeof(struct RESP_CTL));
			q_msg.mtype = 1;
			q_msg.type = 6;
			q_msg.sockfd = msg.sockfd;
			strncpy(q_msg.origin, msg.origin, ORIGIN_SIZE - 1);
			if(msg.payload[0] == '\x01'){
				resp.code = 1;
				strncpy(resp.description, "You are not logined.\x00",21);
				memcpy(q_msg.payload, &resp, sizeof(struct RESP_ROOMS));
				if(msgsnd(key_id2, (void *) &q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
					perror("Error on sending failed by session rooms handle->response");
					exit(0);
				}
			}
			//resp5 : not playing
			//resp255 : fatal error
			//resp6 : not owner of the room
			//resp4 : unknown command argument
			//resp3 : unknown conmand 
			//resp2 : cookie is invalid
			//resp1 : cookie is not settled
			else if(msg.payload[0] == '\x00'){
				struct MSG_CTL *p = (struct MSG_CTL *) &msg.payload[1];
				struct SESSION *s = NULL;
				char cookie[33];
				int i = 0; int j = 0;
				bzero(cookie, sizeof(cookie));
				strncpy(cookie, p->sessid, 32);
				HASH_FIND_STR(sessions, cookie, s);
				if(s){
					if(s->USER_STATUS != USER_PLAY){
						resp.code = 5;
						strncpy(resp.description, "You are not playing game.\x00", 26);
						memcpy(q_msg.payload, &resp, sizeof(struct RESP_CTL));
						if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
							exit(1);
						}
					}
					else{
						int room_idx = -1;
						int player_idx = get_id_by_session(p->sessid);
						for(i = 0 ; i < GAMEMAX ; i++){
							for(j = 0 ; j < 4 ; j++){
								if(s->idx == rooms[i].player[j]){
									room_idx = i;
									break;
								}
							}
						}
						if(room_idx == -1){
							resp.code = 255;
							strncpy(resp.description, "This never meant to be called(FATAL 0)!\x00", 40);
							memcpy(q_msg.payload, &resp, sizeof(struct RESP_CTL));
							if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0 ) == -1){
								exit(1);
							}
						}
						else{
							if(p->CONTROL_MSG == CTL_START){
								bool owning_game = false;
								if(rooms[room_idx].owner == player_idx){
									owning_game = true;
								}
								if(!owning_game){
									resp.code = 6;
									strncpy(resp.description, "You are not owner of the room!\x00", 31);
									memcpy(q_msg.payload, &resp, sizeof(struct RESP_CTL));
									if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0 ) == -1){
										exit(1);
									}
								}
								else{
									rooms[room_idx].GR_STATUS = GR_PLAY;
									bool everyone_idle = true;
									for(i = 0 ; i < 4 ; i++){
										if(rooms[room_idx].PLAYER_STATUS[i] != GR_IDLE){
											if(rooms[room_idx].PLAYER_STATUS[i] != GR_UNUSED){
												everyone_idle = false;
												break;
											}
										}
									}
									if(!everyone_idle){
										resp.code = 7;
										strncpy(resp.description, "Some player is not idle!\x00", 25);
										memcpy(q_msg.payload, &resp, sizeof(struct RESP_CTL));
										if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
											exit(1);
										}
									}
									else{
										for(i = 0 ; i < 4 ; i++){
											if(rooms[room_idx].PLAYER_STATUS[i] == GR_IDLE)
												rooms[room_idx].PLAYER_STATUS[i] = GR_PLAY;
										}
										resp.code = 0;
										strncpy(resp.description, "Successfully played the game.\x00", 30);
										memcpy(q_msg.payload, &resp, sizeof(struct RESP_CTL));
										if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long),0) == -1){
											exit(1);
										}
									}
								}
							}
							else if(p->CONTROL_MSG == CTL_CHANGE){
								if(p->CONTROL_ARG == -1){
									resp.code = 4;
									strncpy(resp.description, "Your command argument is unknown!\x00", 34);
									memcpy(q_msg.payload, &resp, sizeof(struct RESP_CTL));
									if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
										exit(1);
									}
								}
								else{
									if(rooms[room_idx].owner == player_idx){
										rooms[room_idx].song = p->CONTROL_ARG;
										resp.code = 0;
										strncpy(resp.description, "Successfully changed song!\x00", 27);
										memcpy(q_msg.payload, &resp, sizeof(struct RESP_CTL));
										if(msgsnd(key_id2, (void *) &q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
											exit(1);
										}
									}
									else{
										resp.code = 6;
										strncpy(resp.description, "You are not owner of the room!\x00", 31);
										memcpy(q_msg.payload, &resp, sizeof(struct RESP_CTL));
										if(msgsnd(key_id2, (void *) &q_msg, sizeof(struct MSG) - sizeof(long), 0 ) == -1){
											exit(1);
										}
									}
								}
							}
							else if(p->CONTROL_MSG == CTL_EXIT){
								bool user_exists = false;
								if(rooms[room_idx].owner == player_idx){
									rooms[room_idx].GR_STATUS = GR_UNUSED;
									rooms[room_idx].owner = 0;
									for(i = 0 ; i < 4 ; i++){
										struct SESSION *iter;
										for(iter = sessions ; iter != NULL ; iter = iter->hh.next){
											if(iter->idx == rooms[room_idx].player[i]){
												iter->USER_STATUS = USER_IDLE;
												printf("found user %d\n", iter->idx);			
											}
										}
										rooms[room_idx].PLAYER_STATUS[i] = GR_UNUSED;
										rooms[room_idx].player[i] = 0;
										bzero(rooms[room_idx].player_id[i], 64);
									}
									bzero(rooms[room_idx].roomname, 64);					
									s->USER_STATUS = USER_IDLE;
									resp.code = 0;
									strncpy(resp.description, "Successfully exited the room.\x00", 30);
									memcpy(q_msg.payload, &resp, sizeof(struct RESP_CTL));
									if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
										exit(1);
									}

								}
								else{
									for(i = 0 ; i < 4 ; i++){
										if(rooms[room_idx].player[i] == player_idx){
											user_exists = true;
											rooms[room_idx].player[i] = 0;
											s->USER_STATUS = USER_IDLE;
											break;
										}
									}
									if(!user_exists){
										resp.code = 255;
										strncpy(resp.description, "This never meant to be called.\x00", 31);
										memcpy(q_msg.payload, &resp, sizeof(struct RESP_CTL));
										if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
											exit(1);
										}
									}
									else{
										if(rooms[room_idx].GR_STATUS == GR_IDLE){
											resp.code = 0;
											strncpy(resp.description, "Successfully exited the room.\x00", 30);
											memcpy(q_msg.payload, &resp, sizeof(struct RESP_CTL));
											if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
												exit(1);
											}
										}
										else{
											resp.code = 7;
											strncpy(resp.description, "Game room is already playing!\x00", 30);
											memcpy(q_msg.payload, &resp, sizeof(struct RESP_CTL));
											if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
												exit(1);
											}
										}
									}
								}
							}
							else{
								resp.code = 3;
								strncpy(resp.description, "Your command is unknown!\x00", 25);
								memcpy(q_msg.payload, &resp, sizeof(struct RESP_CTL));
								if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
									exit(1);
								}
							}
						}
					}
				}
				else{
					resp.code = 2;
					strncpy(resp.description, "Your session is unknown or closed.\x00", 34);
					memcpy(q_msg.payload, &resp, sizeof(struct RESP_CTL));
					if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
						exit(1);
					}
				}
			}
		}
		//resp0 : success
		//resp1 : session is not set
		//resp2 : session is unknown or closed
		//resp3 : not playing status
		//resp4 : cannot find user in game list
		//resp5 : game is already closed
		else if(msg.type == 7){
			struct MSG q_msg;
			struct RESP_GDATA resp;
			bzero((char *)&q_msg, sizeof(struct MSG));
			bzero((char *)&resp, sizeof(struct RESP_GDATA));
			q_msg.mtype = 1;
			q_msg.type = 7;
			q_msg.sockfd = msg.sockfd;
			strncpy(q_msg.origin, msg.origin, ORIGIN_SIZE-1);
			if(msg.payload[0] == '\x01'){
				resp.code = 1;
				strncpy(resp.description, "You are not logined.\x00", 21);
				memcpy(q_msg.payload, &resp, sizeof(struct RESP_GDATA));
				if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0 ) == -1){
					exit(1);
				}
			}
			else if(msg.payload[0] == '\x00'){
				struct MSG_GDATA *p = (struct MSG_GDATA *) &msg.payload[1];
				struct SESSION *s = NULL;
				char cookie[33];
				int i = 0 ; int j = 0;
				bzero(cookie ,sizeof(cookie));
				strncpy(cookie, p->sessid, 32);
				HASH_FIND_STR(sessions, cookie, s);
				if(s){
					int room_idx = -1;
					int room_player_idx = -1;
					int player_idx = get_id_by_session(p->sessid);
					int player_count = 0;
					if(s->USER_STATUS != USER_PLAY){
						resp.code = 3;
						strncpy(resp.description, "You are not playing!\x00", 21);
						memcpy(q_msg.payload, &resp, sizeof(struct RESP_GDATA));
						if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
							exit(1);
						}
					}
					else{
						for(i = 0 ; i < GAMEMAX ; i++){
							for(j = 0 ; j < 4 ; j++){
								if(s->idx == rooms[i].player[j]){
									room_idx = i;
									room_player_idx = j;
									break;
								}
							}
						}
						for(i = 0 ; i < 4 ; i++){
							if(rooms[room_idx].player[i] != 0){
								player_count++;
							}
						}
						if( room_idx == -1 || room_player_idx == -1){
							resp.code = 4;
							strncpy(resp.description, "Cannot find user in game list!\x00", 31);
							memcpy(q_msg.payload, &resp, sizeof(struct RESP_GDATA));
							if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
								exit(1);
							}
						}
						else{
							if(rooms[room_idx].PLAYER_STATUS[room_player_idx] != GR_PLAY){
								resp.code = 5;
								strncpy(resp.description, "You are not playing!\x00", 21);
								memcpy(&resp.room_info, &rooms[room_idx], sizeof(struct GAMEROOM));
								memcpy(q_msg.payload, &resp, sizeof(struct RESP_GDATA));
								if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
									exit(1);
								}
							}
							else{
								if(p->GDATA_SCORE != -1){
									if(rooms[room_idx].PLAYER_STATUS[room_player_idx] == GR_PLAY){
										rooms[room_idx].score[room_player_idx] = p->GDATA_SCORE;
									}
								}
								if(p->GDATA_STATUS != -1 && p->GDATA_STATUS != 0 && p->GDATA_STATUS != 1){
									rooms[room_idx].PLAYER_STATUS[room_player_idx] = p->GDATA_STATUS;
								}
								int player_tmp = 0;
								for(i = 0 ; i < 4 ; i++){
									if(rooms[room_idx].PLAYER_STATUS[i] == GR_RESULT){
										player_tmp++;
									}
								}      
								if(player_tmp == player_count){
									rooms[room_idx].GR_STATUS = GR_RESULT;
								}
								resp.code = 0;
								strncpy(resp.description, "Successfully saved your data.\x00", 30);
								memcpy(&resp.room_info, &rooms[room_idx], sizeof(struct GAMEROOM));
								memcpy(q_msg.payload, &resp, sizeof(struct RESP_GDATA));
								if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
									exit(1);
								}
							}
						}
					}
				}else{
					resp.code = 2;
					strncpy(resp.description, "Your session is unknown or closed.\x00", 34);
					memcpy(q_msg.payload, &resp, sizeof(struct RESP_GDATA));
					if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
						exit(1);
					}
				}
			}

		}
		else if(msg.type == 8){
			struct MSG q_msg;
			struct RESP_RESULT resp;
			bzero((char *)&q_msg, sizeof(struct MSG));
			bzero((char *)&resp, sizeof(struct RESP_RESULT));
			q_msg.mtype = 1;
			q_msg.type = 8;
			q_msg.sockfd = msg.sockfd;
			strncpy(q_msg.origin, msg.origin, ORIGIN_SIZE-1);
			if(msg.payload[0] == '\x01'){
				resp.code = 1;
				strncpy(resp.description, "You are not logined.\x00",21);
				memcpy(q_msg.payload, &resp, sizeof(struct RESP_RESULT));
				if(msgsnd(key_id2, (void *) &q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
					perror("Error on sending failed by session rooms handle->response");
					exit(0);
				}
			}
			else{
				struct MSG_RESULT *p = (struct MSG_RESULT *)&msg.payload[1];
				struct SESSION *s = NULL;
				char cookie[33];
				int i = 0 ; int j = 0;
				strncpy(cookie, p->sessid, 32);
				HASH_FIND_STR(sessions, cookie, s);
				if(s){
					if(s->USER_STATUS != USER_PLAY){
						resp.code = 3;
						strncpy(resp.description, "You are not playing!\x00", 21);
						memcpy(q_msg.payload, &resp, sizeof(struct RESP_GDATA));
						if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
							exit(1);
						}	
					}
					else{
						int room_idx = -1;
						int room_player_idx = -1;
						int player_idx = get_id_by_session(p->sessid);
						int total_player = 0;
						int fetched_player = 0;
						int player_count = 0;
						for(i = 0 ; i < GAMEMAX ; i++){
							for(j = 0 ; j < 4; j++){
								if(rooms[i].player[j] == player_idx){
									room_idx = i;
									room_player_idx = j;
									break;
								}
							}
						}
						for(i = 0 ; i < 4 ; i++){
							if(rooms[room_idx].player[i] != 0){
								player_count++;
							}
						}
						if( room_idx == -1 || room_player_idx == -1){
							resp.code = 4;
							strncpy(resp.description, "Cannot find user in game list!\x00", 31);
							memcpy(q_msg.payload, &resp, sizeof(struct RESP_GDATA));
							if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
								exit(1);
							}
						}
						else{
							if(rooms[room_idx].GR_STATUS != GR_RESULT){
								resp.code = 5;
								strncpy(resp.description, "Game is not finished!\x00", 22);
								memcpy(q_msg.payload, &resp, sizeof(struct RESP_RESULT));
								if(msgsnd(key_id2, (void *) &q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
									exit(1);
								}
							}
							else{
								rooms[room_idx].PLAYER_STATUS[room_player_idx] = GR_IDLE;
								for(i = 0 ; i <4 ; i++){
									if(rooms[room_idx].PLAYER_STATUS[i] == GR_IDLE){
										fetched_player++;
									}
								}
								if(fetched_player == total_player){
									rooms[room_idx].GR_STATUS = GR_IDLE;
								}
								resp.code = 0;
								strncpy(resp.description, "Successfully fetched result!\x00", 29);
								memcpy(&resp.room_info, &rooms[room_idx], sizeof(struct GAMEROOM));
								memcpy(q_msg.payload, &resp, sizeof(struct RESP_RESULT));
								if(msgsnd(key_id2, (void *) &q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
									exit(1);
								}
							}
						}
					}
				}
				else{
					resp.code = 2;
					strncpy(resp.description, "Your session is unknown or closed.\x00", 34);
					memcpy(q_msg.payload, &resp, sizeof(struct RESP_RESULT));
					if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
						exit(1);
					}
				}
			}
		}
		else if(msg.type == 9){
			struct MSG q_msg;
			struct RESP_STATUS resp;
			bzero((char *)&q_msg, sizeof(struct MSG));
			bzero((char *)&resp, sizeof(struct RESP_STATUS));
			q_msg.mtype = 1;
			q_msg.type = 9;
			q_msg.sockfd = msg.sockfd;
			strncpy(q_msg.origin, msg.origin, ORIGIN_SIZE - 1);
			if(msg.payload[0] == '\x01'){
				printf("not logined!\n");
				resp.code = 1;
				strncpy(resp.description, "You are not logined.\x00",21);
				memcpy(q_msg.payload, &resp, sizeof(struct RESP_STATUS));
				if(msgsnd(key_id2, (void *) &q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
					perror("Error on sending failed by session rooms handle->response");
					exit(0);
				}
			}
			else{
				struct MSG_STATUS *p = (struct MSG_STATUS *)&msg.payload[1];
				char cookie[33];
				struct SESSION *s = NULL;
				bzero(cookie, sizeof(cookie));
				strncpy(cookie, p->sessid, SESS_SIZE - 1);
				HASH_FIND_STR(sessions, cookie, s);
				if(s){
					if(s->USER_STATUS != USER_PLAY){
						resp.code = 3;
						strncpy(resp.description, "You are not playing!\x00", 21);
						memcpy(q_msg.payload, &resp, sizeof(struct RESP_STATUS));
						if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
							exit(1);
						}
					}
					else{
						int room_idx = -1;
						int player_idx = get_id_by_session(p->sessid);
						int i = 0; int j = 0;
						for(i = 0 ; i < GAMEMAX ; i++){
							for(j = 0 ; j < 4 ; j++){
								if(rooms[i].player[j] == player_idx){
									room_idx = i;
									break;
								}
							}
						}
						if(room_idx == -1){
							resp.code = 4;
							strncpy(resp.description, "Cannot find user in game list!\x00", 31);
							memcpy(q_msg.payload, &resp, sizeof(struct RESP_STATUS));
							if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
								exit(1);
							}
						}
						else{
							resp.code = 0;
							strncpy(resp.description, "Succesfully fetched your game info.\x00", 36);
							memcpy(&resp.room_info, &rooms[room_idx], sizeof(struct GAMEROOM));
							memcpy(q_msg.payload, &resp, sizeof(struct RESP_STATUS));
							if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
								exit(1);
							}
						}
					}
				}
				else{
					resp.code = 2;
					strncpy(resp.description, "Your session is unknown or closed.\x00", 34);
					memcpy(q_msg.payload, &resp, sizeof(struct RESP_STATUS));
					if(msgsnd(key_id2, (void *)&q_msg, sizeof(struct MSG) - sizeof(long), 0) == -1){
						exit(1);
					}
				}
			}
		}
		else{
			char tmpbuf[LINE_MAX];
			snprintf(tmpbuf, LINE_MAX, "unknown message type : %lu\n", msg.type);
			_log(LOG_NORMAL, tmpbuf);
			return;
		}
	}
}

char *encode(unsigned char hashed[]){
	char *tmp = malloc(33);
	bzero(tmp,sizeof(tmp));
	int i = 0;
	for(i = 0 ; i < MD5_DIGEST_LENGTH ; i++){
		sprintf(tmp,"%s%02x",tmp,hashed[i]);
	}
	return tmp;
}

char *gen_rand32(){
	int randomData = open("/dev/urandom", O_RDONLY);
	char *encoded=NULL;
	char rbuf[16];
	if(read(randomData, rbuf,16) == 16){
		encoded = encode(rbuf);
	}
	close(randomData);
	return encoded;
}
void checkResp(){
	struct MSG msg;
	char tmpbuf[LINE_MAX];
	bzero((char *)&msg, sizeof(struct MSG));
	if(msgrcv(host_key, (void *)&msg, sizeof(struct MSG) - sizeof(long), 0, IPC_NOWAIT) == -1){
		return;
	}
	//msg.mtype = 1
	//msg.type = [1~9]	
	snprintf(tmpbuf, LINE_MAX, "Response fetched %ld", msg.type);
	_log(LOG_NORMAL, tmpbuf);
	send(msg.sockfd, "HTTP/1.1 200 OK\r\n", 16, 0);
	char origin[256];
	bzero(origin, sizeof(origin));
	snprintf(origin, 256, "Access-Control-Allow-Origin: %s\r\n", msg.origin);
	send(msg.sockfd, "Content-Type: application/json\r\n", 32, 0);
	send(msg.sockfd, "Access-Control-Allow-Methods: POST\r\n", 36, 0);
	send(msg.sockfd, origin, strlen(origin)-1, 0);
	send(msg.sockfd, "Access-Control-Allow-Credentials: true\r\n",40, 0);
	//response, json objectify struct
	if(msg.type == 1){
		char tmp[512];
		struct RESP_LOGIN *p = (struct RESP_LOGIN *)msg.payload;
		json_object *jobj = json_object_new_object();
		json_object *jcode = json_object_new_int(p->code);
		json_object *jdesc = json_object_new_string(p->description);
		json_object_object_add(jobj,"code", jcode);
		json_object_object_add(jobj,"description", jdesc);
		bzero(tmp, sizeof(tmp));
		snprintf(tmp, 512, "Set-Cookie: session=%s;\r\n", p->sessid);
		if(p->code == 0)
			send(msg.sockfd, tmp, strlen(tmp), 0);
		send(msg.sockfd, "\r\n", 2, 0);
		bzero(tmp, sizeof(tmp));
		strncpy(tmp, json_object_to_json_string(jobj), 512);
		send(msg.sockfd, tmp, strlen(tmp), 0);
		free(jobj);
		free(jcode);
		free(jdesc);
	}
	else if(msg.type == 2){
		char tmp[512];
		struct RESP_REGISTER *p = (struct RESP_REGISTER *)msg.payload;
		json_object *jobj = json_object_new_object();
		json_object *jcode = json_object_new_int(p->code);
		json_object *jdesc = json_object_new_string(p->description);
		json_object_object_add(jobj,"code",jcode);
		json_object_object_add(jobj,"description", jdesc);
		bzero(tmp, sizeof(tmp));
		strncpy(tmp, json_object_to_json_string(jobj), 512);
		send(msg.sockfd, "\r\n", 2, 0);
		send(msg.sockfd, tmp, strlen(tmp), 0);
		free(jobj);
		free(jcode);
		free(jdesc);
	}
	else if(msg.type == 3){
		char tmp[2048];
		struct RESP_ROOMS *p = (struct RESP_ROOMS *)msg.payload;
		int i = 0;
		int j = 0;
		json_object *jobj = json_object_new_object();
		json_object *jcode = json_object_new_int(p->code);
		json_object *jdesc = json_object_new_string(p->description);
		json_object_object_add(jobj, "code", jcode);
		json_object_object_add(jobj, "description", jdesc);
		send(msg.sockfd, "\r\n", 2, 0);
		bzero(tmp, sizeof(tmp));
		if(p->code == 0){
			json_object *jarray1 = json_object_new_array();
			for(i = 0 ; i < GAMEMAX ; i++){
				json_object *jarray2 = json_object_new_object();
				json_object *jidx = json_object_new_int(p->rooms[i].song);
				json_object *jowner = json_object_new_int(p->rooms[i].owner);
				json_object *jroomname = json_object_new_string(p->rooms[i].roomname);
				json_object *jarray3 = json_object_new_array();
				for(j = 0 ; j < 4 ; j++){
					json_object *jp = json_object_new_int(p->rooms[i].player[j]);
					json_object_array_add(jarray3, jp);
				}
				json_object *jstatus = json_object_new_int(p->rooms[i].GR_STATUS);
				json_object_object_add(jarray2, "song", jidx);
				json_object_object_add(jarray2, "owner", jowner);
				json_object_object_add(jarray2, "roomname", jroomname);
				json_object_object_add(jarray2, "player", jarray3);
				json_object_object_add(jarray2, "status", jstatus);
				json_object_array_add(jarray1, jarray2);
			}
			json_object_object_add(jobj, "data", jarray1);
			strncpy(tmp, json_object_to_json_string(jobj), 2048);
			send(msg.sockfd, tmp, strlen(tmp), 0);	
		}
		else{
			strncpy(tmp, json_object_to_json_string(jobj), 2048);
			send(msg.sockfd, tmp, strlen(tmp), 0);
		}
		free(jobj);
		free(jcode);
		free(jdesc);		
	}
	else if(msg.type == 4){
		char tmp[512];
		struct RESP_CREATE *p = (struct RESP_CREATE *)msg.payload;
		json_object *jobj = json_object_new_object();
		json_object *jcode = json_object_new_int(p->code);
		json_object *jdesc = json_object_new_string(p->description);
		json_object *jidx = NULL;
		json_object_object_add(jobj, "code", jcode);
		json_object_object_add(jobj, "description", jdesc);
		send(msg.sockfd, "\r\n", 2, 0);
		bzero(tmp, sizeof(tmp));
		if(p->code == 0){
			jidx = json_object_new_int(p->room_idx);
			json_object_object_add(jobj, "room_idx", jidx);
		}
		strncpy(tmp, json_object_to_json_string(jobj), 512);
		send(msg.sockfd, tmp, strlen(tmp), 0);
		if(p->code == 0 && jidx != NULL){
			free(jidx);
		}
		free(jobj);
		free(jcode);
		free(jdesc);
	}
	else if(msg.type == 5){
		char tmp[512];
		struct RESP_JOIN *p = (struct RESP_JOIN *)msg.payload;
		json_object *jobj = json_object_new_object();
		json_object *jcode = json_object_new_int(p->code);
		json_object *jdesc = json_object_new_string(p->description);
		json_object_object_add(jobj, "code", jcode);
		json_object_object_add(jobj, "description", jdesc);
		send(msg.sockfd, "\r\n", 2, 0);	
		bzero(tmp, sizeof(tmp));
		strncpy(tmp, json_object_to_json_string(jobj), 512);
		send(msg.sockfd, tmp, strlen(tmp), 0);
		free(jobj);
		free(jcode);
		free(jdesc);
	}
	else if(msg.type == 6){
		char tmp[512];
		struct RESP_CTL *p = (struct RESP_CTL *)msg.payload;
		json_object *jobj = json_object_new_object();
		json_object *jcode = json_object_new_int(p->code);
		json_object *jdesc = json_object_new_string(p->description);
		json_object_object_add(jobj, "code", jcode);
		json_object_object_add(jobj, "description", jdesc);
		send(msg.sockfd, "\r\n", 2, 0);
		bzero(tmp, sizeof(tmp));
		strncpy(tmp, json_object_to_json_string(jobj), 512);
		send(msg.sockfd, tmp, strlen(tmp), 0);
		free(jobj);
		free(jcode);
		free(jdesc);
	}
	else if(msg.type == 7){
		char tmp[1024];
		struct RESP_GDATA *p = (struct RESP_GDATA *)msg.payload;
		int i = 0;
		json_object *jobj = json_object_new_object();
		json_object *jcode = json_object_new_int(p->code);
		json_object *jdesc = json_object_new_string(p->description);
		json_object_object_add(jobj, "code", jcode);
		json_object_object_add(jobj, "description", jdesc);
		if(p->code == 0 || p->code == 5){
			json_object *jroom = json_object_new_object();
			json_object *jarray_player = json_object_new_array();
			json_object *jarray_player_id = json_object_new_array();
			json_object *jplayer_status = json_object_new_array();
			json_object *jarray_score = json_object_new_array();
			for(i = 0 ; i < 4; i++){
				json_object *jplayer = json_object_new_int(p->room_info.player[i]);
				json_object *jplayer_id = json_object_new_string(p->room_info.player_id[i]);
				json_object *jpstatus = json_object_new_int(p->room_info.PLAYER_STATUS[i]);
				json_object *jscore = json_object_new_int(p->room_info.score[i]);
				json_object_array_add(jarray_player, jplayer);
				json_object_array_add(jplayer_status, jpstatus);
				json_object_array_add(jarray_player_id, jplayer_id);
				json_object_array_add(jarray_score, jscore);
			}
			json_object *jstatus = json_object_new_int(p->room_info.GR_STATUS);
			json_object *jsong = json_object_new_int(p->room_info.song);
			json_object_object_add(jroom, "player", jarray_player);
			json_object_object_add(jroom, "player_id", jarray_player_id);
			json_object_object_add(jroom, "player_status", jplayer_status);
			json_object_object_add(jroom, "score", jarray_score);
			json_object_object_add(jroom, "room_status", jstatus);
			json_object_object_add(jroom, "song", jsong);
			json_object_object_add(jobj, "room", jroom);
		}
		send(msg.sockfd, "\r\n", 2, 0);     
		bzero(tmp, sizeof(tmp));
		strncpy(tmp, json_object_to_json_string(jobj), 1024);
		send(msg.sockfd, tmp, strlen(tmp), 0);
		free(jobj);
		free(jcode);
		free(jdesc);
	}
	else if(msg.type == 8){
		char tmp[1024];
		struct RESP_RESULT *p = (struct RESP_RESULT *) msg.payload;
		int i = 0;
		json_object *jobj = json_object_new_object();
		json_object *jcode = json_object_new_int(p->code);
		json_object *jdesc = json_object_new_string(p->description);
		json_object_object_add(jobj, "code", jcode);
		json_object_object_add(jobj, "description", jdesc);
		if(p->code == 0){
			json_object *jroom = json_object_new_object();
			json_object *jarray_player = json_object_new_array();
			json_object *jarray_player_id = json_object_new_array();
			json_object *jplayer_status = json_object_new_array();
			json_object *jarray_score = json_object_new_array();
			for(i = 0 ; i < 4; i++){
				json_object *jplayer = json_object_new_int(p->room_info.player[i]);
				json_object *jplayer_id = json_object_new_string(p->room_info.player_id[i]);
				json_object *jpstatus = json_object_new_int(p->room_info.PLAYER_STATUS[i]);
				json_object *jscore = json_object_new_int(p->room_info.score[i]);
				json_object_array_add(jarray_player, jplayer);
				json_object_array_add(jplayer_status, jpstatus);
				json_object_array_add(jarray_player_id, jplayer_id);
				json_object_array_add(jarray_score, jscore);
			}
			json_object *jstatus = json_object_new_int(p->room_info.GR_STATUS);
			json_object *jsong = json_object_new_int(p->room_info.song);
			json_object_object_add(jroom, "player", jarray_player);
			json_object_object_add(jroom, "player_id", jarray_player_id);
			json_object_object_add(jroom, "player_status", jplayer_status);
			json_object_object_add(jroom, "score", jarray_score);
			json_object_object_add(jroom, "room_status", jstatus);
			json_object_object_add(jroom, "song", jsong);
			json_object_object_add(jobj, "room", jroom);
		}

		send(msg.sockfd, "\r\n", 2, 0);
		bzero(tmp, sizeof(tmp));
		strncpy(tmp, json_object_to_json_string(jobj), 1024);
		send(msg.sockfd, tmp, strlen(tmp), 0);
		free(jobj);
		free(jcode);
		free(jdesc);

	}
	else if(msg.type == 9){
		char tmp[1024];
		struct RESP_RESULT *p = (struct RESP_RESULT *) msg.payload;
		int i = 0;
		json_object *jobj = json_object_new_object();
		json_object *jcode = json_object_new_int(p->code);
		json_object *jdesc = json_object_new_string(p->description);
		json_object_object_add(jobj, "code", jcode);
		json_object_object_add(jobj, "description", jdesc);
		if(p->code == 0){
			json_object *jroom = json_object_new_object();
			json_object *jarray_player = json_object_new_array();
			json_object *jarray_player_id = json_object_new_array();
			json_object *jplayer_status = json_object_new_array();
			json_object *jarray_score = json_object_new_array();
			for(i = 0 ; i < 4; i++){
				json_object *jplayer = json_object_new_int(p->room_info.player[i]);
				json_object *jplayer_id = json_object_new_string(p->room_info.player_id[i]);
				json_object *jpstatus = json_object_new_int(p->room_info.PLAYER_STATUS[i]);
				json_object *jscore = json_object_new_int(p->room_info.score[i]);
				json_object_array_add(jarray_player, jplayer);
				json_object_array_add(jplayer_status, jpstatus);
				json_object_array_add(jarray_player_id, jplayer_id);
				json_object_array_add(jarray_score, jscore);
			}
			json_object *jstatus = json_object_new_int(p->room_info.GR_STATUS);
			json_object *jsong = json_object_new_int(p->room_info.song);
			json_object_object_add(jroom, "player", jarray_player);
			json_object_object_add(jroom, "player_id", jarray_player_id);
			json_object_object_add(jroom, "player_status", jplayer_status);
			json_object_object_add(jroom, "score", jarray_score);
			json_object_object_add(jroom, "room_status", jstatus);
			json_object_object_add(jroom, "song", jsong);
			json_object_object_add(jobj, "room", jroom);
		}
		send(msg.sockfd, "\r\n", 2, 0);
		bzero(tmp, sizeof(tmp));
		strncpy(tmp, json_object_to_json_string(jobj), 1024);
		send(msg.sockfd, tmp, strlen(tmp), 0);
		free(jobj);
		free(jcode);
		free(jdesc);

	}

	shutdown(msg.sockfd, SHUT_RDWR);
	close(msg.sockfd);
	clients[msg.sockfd] = -1;
}

void init_gameroom(){
	int i = 0;
	int j = 0;
	char tmpbuf[LINE_MAX];
	bzero(tmpbuf, LINE_MAX);
	snprintf(tmpbuf, LINE_MAX, "[LOG] Initializing game rooms..");
	_log(LOG_NORMAL, tmpbuf);
	for(i = 0 ; i < GAMEMAX ; i++){
		rooms[i].song = 0;
		rooms[i].owner = 0;
		bzero((char *) rooms[i].roomname, sizeof(rooms[i].roomname));
		rooms[i].GR_STATUS = GR_UNUSED;

		for(j = 0 ; j < 4 ; j++){
			rooms[i].player[j] = 0;
			bzero(rooms[i].player_id[j], 64);
			rooms[i].score[j] = 0;
			rooms[i].PLAYER_STATUS[j] = 0;
		}
	}
}

int get_idx_available(){
	int i = 0;
	for(i = 0 ; i < GAMEMAX ; i++){
		if(rooms[i].GR_STATUS == GR_UNUSED)
			return i;
	}
	return -1;
}
int get_id_by_session(char *sessval){
	struct SESSION *p = NULL;
	char cookie[33];
	bzero(cookie, sizeof(cookie));
	strncpy(cookie, sessval, SESS_SIZE-1);
	HASH_FIND_STR(sessions, cookie, p);
	if(p){
		return p->idx;
	}
	return -1;
}
char *get_name_by_session(char *sessval){
	struct SESSION *p = NULL;
	char cookie[33];
	bzero(cookie, sizeof(cookie));
	strncpy(cookie, sessval, 32);
	HASH_FIND_STR(sessions, cookie, p);
	if(p){
		char *ret = malloc(64);
		strncpy(ret, p->id, 64);
		return ret;
	}
	return NULL;
}
int get_status_by_session(char *sessval){
	struct SESSION *p = NULL;
	char cookie[33];
	bzero(cookie, sizeof(cookie));
	strncpy(cookie, sessval, 32);
	HASH_FIND_STR(sessions, cookie, p);
	if(p){
		return p->USER_STATUS;
	}
	return -1;
}
char *get_name_by_idx(int idx){
	return NULL;
}

void _log(int LEVEL, char *buf){
	char buffer[LINE_MAX];
	const int LEV = 2;
	int i = 0;
	char LEVELS[LEV][16];
	for(i = 0 ; i < 2 ; i++){
		bzero(LEVELS[i], 16);
	}
	strncpy(LEVELS[LOG_NORMAL], "NORMAL", 6);
	strncpy(LEVELS[LOG_DEBUG], "DEBUG", 5);
	FILE *fp = fopen("log", "a");
	if(fp == NULL){
		perror("Failed to open log file");
		return;
	}
	snprintf(buffer, LINE_MAX, "[%s] %s\n",LEVELS[LEVEL], buf);
	fwrite(buffer, sizeof(char), strlen(buffer), fp);
	fclose(fp);
}
