/* Copyright (C) 2023 John Törnblom

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

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <notify.hpp>
#include <klog.hpp>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <ps5/kernel.h>

static void
list_dir(const char *base_path)
{
  char tmp_path[PATH_MAX + 1];
  struct stat statbuf;
  struct dirent *dp;
  DIR *dir;

  if (!(dir = opendir(base_path)))
  {
    perror(base_path);
    return;
  }

  while ((dp = readdir(dir)))
  {
    if (!strcmp(dp->d_name, "."))
    {
      continue;
    }

    if (!strcmp(dp->d_name, ".."))
    {
      continue;
    }

    strncpy(tmp_path, base_path, PATH_MAX);
    strncat(tmp_path, "/", PATH_MAX);
    strncat(tmp_path, dp->d_name, PATH_MAX);

    if (stat(tmp_path, &statbuf))
    {
      perror(tmp_path);
      continue;
    }

    if (S_ISDIR(statbuf.st_mode))
    {
      list_dir(tmp_path);
    }
    else
    {
      printf("%s\n", tmp_path + 1);
    }
  }
  closedir(dir);
}

int main()
{

  if(!redirct_stdout()){
    return EXIT_FAILURE;
  }

  puts("================== Listing files in /mnt/usb1 =================");
  list_dir("/mnt/usb1");
  puts("================== END OF SAMPLE  ============================");

  return EXIT_SUCCESS;
}