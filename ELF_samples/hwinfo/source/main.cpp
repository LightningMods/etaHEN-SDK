#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <notify.hpp>

extern "C"
{
	int sceKernelGetHwModelName(char *);
	int sceKernelGetHwSerialNumber(char *);
	long sceKernelGetCpuFrequency(void);
	int sceKernelGetCpuTemperature(int *);
	int sceKernelGetSocSensorTemperature(int, int *);
}

void notify(const char *text, ...)
{
	OrbisNotificationRequest noti_buffer;

	va_list args;
	va_start(args, text);
	vsprintf(noti_buffer.message, text, args);
	va_end(args);

	noti_buffer.type = 0;
	noti_buffer.unk3 = 0;
	noti_buffer.use_icon_image_uri = 1;
	noti_buffer.target_id = -1;
	strcpy(noti_buffer.uri, "cxml://psnotification/tex_icon_system");

	sceKernelSendNotificationRequest(0, &noti_buffer, sizeof(noti_buffer), 0);
}

int main(int argc, char **argv)
{
	notify("[Test ELF] Hello World from the ELF loader");

	char s[2000];
	int temp = 0;
	long cpuFreq;

	s[0] = '\0'; // Ensuring the string is initially empty

	// Using a temporary buffer for formatted strings before concatenation
	char tempBuf[256];
	char hwbuf[256];
	snprintf(s, sizeof(s), "========== Console Info ============\n"); // Appending to the main buffer

	if (sceKernelGetHwModelName(hwbuf))
	{
		perror("sceKernelGetHwModelName");
		notify("Error getting model name");
	}
	else
	{
		sprintf(tempBuf, "Model: %s\n", hwbuf);
		strcat(s, tempBuf); // Appending to the main buffer
	}

	if (sceKernelGetHwSerialNumber(hwbuf))
	{
		perror("sceKernelGetHwSerialNumber");
	}
	else
	{
		sprintf(tempBuf, "S/N: %s\n", hwbuf);
		//sprintf(tempBuf, "S/N: CENSORED FOR DEMO\n", hwbuf);
		strcat(s, tempBuf);
	}

	if (sceKernelGetSocSensorTemperature(0, &temp))
	{
		perror("sceKernelGetSocSensorTemperature");
	}
	else
	{
		sprintf(tempBuf, "SoC temp: %d °C\n", temp);
		strcat(s, tempBuf);
	}

	if (sceKernelGetCpuTemperature(&temp))
	{
		perror("sceKernelGetCpuTemperature");
	}
	else
	{
		sprintf(tempBuf, "CPU temp: %d °C\n", temp);
		strcat(s, tempBuf);
	}

	cpuFreq = sceKernelGetCpuFrequency() / (1000 * 1000); // Assuming this function exists and returns the CPU frequency in Hz
	sprintf(tempBuf, "CPU freq: %2.2ld MHz\n", cpuFreq);
	strcat(s, tempBuf);

	notify(s);

	return 0;
}