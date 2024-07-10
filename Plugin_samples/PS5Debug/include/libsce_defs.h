#pragma once
#include <sys/socket.h>
#include <stdint.h>
#include "types.h"


typedef struct
{
	int32_t type;			 // 0x00
	int32_t req_id;			 // 0x04
	int32_t priority;		 // 0x08
	int32_t msg_id;			 // 0x0C
	int32_t target_id;		 // 0x10
	int32_t user_id;		 // 0x14
	int32_t unk1;			 // 0x18
	int32_t unk2;			 // 0x1C
	int32_t app_id;			 // 0x20
	int32_t error_num;		 // 0x24
	int32_t unk3;			 // 0x28
	char use_icon_image_uri; // 0x2C
	char message[1024];		 // 0x2D
	char uri[1024];			 // 0x42D
	char unkstr[1024];		 // 0x82D
} OrbisNotificationRequest;	 // Size = 0xC30



int sceNetSocket(const char*, int, int, int);
int sceNetSocketClose(int);
int sceNetConnect(int, struct sockaddr *, int);
int sceNetSend(int, const void *, size_t, int);
int sceNetBind(int, struct sockaddr *, int);
int sceNetListen(int, int);
int sceNetAccept(int, struct sockaddr *, unsigned int *);
int sceNetRecv(int, void *, size_t, int);
int sceNetSocketAbort(int, int);
int sceNetSetsockopt(int s, int level, int optname, const void *optval, socklen_t optlen);
int sceNetRecvfrom(int s, void *buf, unsigned int len, int flags, struct sockaddr *from, unsigned int *fromlen);
int sceNetSendto(int s, void *msg, unsigned int len, int flags, struct sockaddr *to, unsigned int tolen);
uint16_t sceNetHtons(uint16_t host16);
unsigned int sceKernelSleep(unsigned int seconds);
int sceKernelUsleep(unsigned int microseconds);
int scePthreadCreate(ScePthread *thread, const ScePthreadAttr *attr, void *entry, void *arg, const char *name);
void scePthreadYield(void);
int sceKernelSendNotificationRequest(int, OrbisNotificationRequest*, size_t, int);