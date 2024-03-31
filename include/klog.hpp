#pragma once
#include <notify.hpp>
#include <fcntl.h>

static bool redirct_stdout(){
  int fd = open("/dev/console", O_WRONLY);
  if (fd == -1)
  {
    notify("Failed to open /dev/console");
    return false;
  }

  dup2(fd, STDOUT_FILENO);
  dup2(STDOUT_FILENO, STDERR_FILENO);
  puts("========== STDOUT Redirected ========");
  return true;
}