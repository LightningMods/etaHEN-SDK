// Credits to astrelsky: https://github.com/astrelsky/HEN-V/blob/master/spawner/source/jailbreak.h
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

void jailbreak_process(pid_t pid, bool escapeSandbox);