/* Copyright (C) 2024 LM & John Törnblom

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