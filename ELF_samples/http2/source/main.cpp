/* Copyright (C) 2024 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <notify.hpp>
#include <fcntl.h>
#include <pthread.h>
typedef pthread_attr_t ScePthreadAttr;
typedef struct sched_param SceKernelSchedParam;
typedef uint64_t SceKernelCpumask;
extern "C"
{

	int sceNetInit();
	int sceNetPoolCreate(const char *, int, int);
	int sceNetPoolDestroy(int);

	int sceSslInit(size_t);
	int sceSslTerm(int);

	int sceHttp2Init(int, int, size_t, int);
	int sceHttp2Term(int);

	int sceHttp2CreateTemplate(int, const char *, int, int);
	int sceHttp2DeleteTemplate(int);

	int sceHttp2CreateRequestWithURL(int, const char *, const char *, uint64_t);
	int sceHttp2DeleteRequest(int);

	int sceHttp2SendRequest(int, const void *, size_t);
	int sceHttp2GetStatusCode(int, int *);
	int sceHttp2ReadData(int, void *, size_t);
	int scePthreadAttrSetschedparam(
		ScePthreadAttr *attr,
		const SceKernelSchedParam *param);
	int scePthreadAttrSetstacksize(ScePthreadAttr *attr, size_t stacksize);
	int scePthreadAttrSetinheritsched(ScePthreadAttr *attr, int inheritsched);
	int scePthreadAttrSetschedpolicy(ScePthreadAttr *attr, int policy);
	int scePthreadAttrSetaffinity(ScePthreadAttr *attr, SceKernelCpumask cpumask);
	int scePthreadAttrInit(ScePthreadAttr *attr);
	int scePthreadAttrDestroy(ScePthreadAttr *attr);
int scePthreadCreate(
    pthread_t *thread, 
    const ScePthreadAttr *attr, 
    void *(*start_routine)(void *), 
    void *arg, 
    const char *name
);
	
int sceKernelIsPs4Process();
}
static int g_libnetMemId = -1;
static int g_libsslCtxId = -1;
static int g_libhttpCtxId = -1;
static int g_tmplId = -1;
static int g_reqId = -1;

/**
 *
 **/
static int
http2_init(const char *agent, const char *url)
{
	if (sceNetInit())
	{
		perror("sceNetInit");
		return -1;
	}

	if ((g_libnetMemId = sceNetPoolCreate("http2_get", 32 * 1024, 0)) < 0)
	{
		perror("sceNetPoolCreate");
		return -1;
	}

	if ((g_libsslCtxId = sceSslInit(256 * 1024)) < 0)
	{
		perror("sceSslInit");
		return -1;
	}

	if ((g_libhttpCtxId = sceHttp2Init(g_libnetMemId, g_libsslCtxId,
									   256 * 1024, 1)) < 0)
	{
		perror("sceHttp2Init");
		return -1;
	}

	if ((g_tmplId = sceHttp2CreateTemplate(g_libhttpCtxId, agent, 3, 1)) < 0)
	{
		perror("sceHttp2CreateTemplate");
		return -1;
	}

	if ((g_reqId = sceHttp2CreateRequestWithURL(g_tmplId, "GET", url, 0)) < 0)
	{
		perror("sceHttp2CreateRequestWithURL");
		return -1;
	}

	return 0;
}

/**
 *
 **/
static int
http2_get(void)
{
	char buf[0x1000];
	int length = -1;
	int status = -1;

	if (sceHttp2SendRequest(g_reqId, NULL, 0))
	{
		perror("sceHttp2SendRequest");
		return -1;
	}

	if (sceHttp2GetStatusCode(g_reqId, &status))
	{
		perror("sceHttp2GetStatusCode");
		return -1;
	}

	if (status == 200)
	{
		while ((length = sceHttp2ReadData(g_reqId, buf, sizeof(buf) - 1)) > 0)
		{
			buf[length] = 0;
			printf("%s", buf);
		}
	}
	else
	{
		printf("Status: %d\n", status);
	}

	return status;
}

/**
 *
 **/
static void
http2_fini(void)
{
	if (g_reqId != -1)
	{
		if (sceHttp2DeleteRequest(g_reqId))
		{
			perror("sceHttp2DeleteRequest");
		}
	}

	if (g_tmplId != -1)
	{
		if (sceHttp2DeleteTemplate(g_tmplId))
		{
			perror("sceHttp2DeleteTemplate");
		}
	}

	if (g_libhttpCtxId != -1)
	{
		if (sceHttp2Term(g_libhttpCtxId))
		{
			perror("sceHttp2Term");
		}
	}

	if (g_libsslCtxId != -1)
	{
		if (sceSslTerm(g_libsslCtxId))
		{
			perror("sceSslTerm");
		}
	}

	if (g_libnetMemId != -1)
	{
		if (sceNetPoolDestroy(g_libnetMemId))
		{
			perror("sceNetPoolDestroy");
		}
	}
}

/**
 *  https://github.com/john-tornblom/ps5-payload-sdk/blob/master/samples/http2_get/main.c
 **/
void* thread(void*){
	printf("Thread started\n");
	return NULL;

}
int main()
{
	int error = 0;

	int fd = open("/dev/console", O_WRONLY);
	if (fd == -1)
	{
		notify("Failed to open /dev/console");
		return 1;
	}

	dup2(fd, STDOUT_FILENO);
	dup2(STDOUT_FILENO, STDERR_FILENO);

	printf("================= Starting HTTP2 Sample =================\n");
	ScePthreadAttr v17;
	SceKernelSchedParam v16;
	v16.sched_priority = 700;
	SceKernelCpumask v11 = 0;
	int v10 = 0;
	pthread_t thr;

	int v9 = scePthreadAttrInit(&v17);
	if (v9 < 0)
	{
		printf("Failed to initialize thread attribute: 0x%08X\n", v9);
	}
	else
	{
		v10 = scePthreadAttrSetstacksize(&v17, 16384);
		if (v10 >= 0)
		{
			puts("scePthreadAttrSetstacksize success");
			v10 = scePthreadAttrSetinheritsched(&v17, 0LL);
			if (v10 >= 0)
			{
				puts("scePthreadAttrSetinheritsched success");
				v10 = scePthreadAttrSetschedpolicy(&v17, 1LL);
				if (v10 >= 0)
				{
					puts("scePthreadAttrSetschedpolicy success");
					v10 = scePthreadAttrSetschedparam(&v17, &v16);
					if (v10 >= 0)
					{
						puts("scePthreadAttrSetschedparam success");
						if (!(unsigned int)sceKernelIsPs4Process()){
							v11 = 0x1FFFLL;
						}
						v10 = scePthreadAttrSetaffinity(&v17, v11);
						puts("scePthreadAttrSetaffinity success");
						 if (v10 >= 0)
							v10 = scePthreadCreate(&thr, &v17, thread, NULL, "thread");
					}
				}
			}
		}
		scePthreadAttrDestroy(&v17);
	}
	printf(" returned %d\n", v10);

	return 0;

	if (!(error = http2_init("http2_get/1.0", "http://192.168.123.176/store.db")))
	{
		error = http2_get();
	}

	printf("http2_get returned %d\n", error);

	http2_fini();

	puts("============== END OF HTTP2 SAMPLE =================");

	return error;
}