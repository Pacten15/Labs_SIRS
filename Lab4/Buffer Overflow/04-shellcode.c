// compile
// gcc 04-shellcode.c -o 04-shellcode -fno-stack-protector -g -m32 -z execstack

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void overflow_function (char *str)
{
  char buffer[100];

  printf("buffer @ %p\n", buffer);
  strcpy(buffer, str);  // Function that copies str to buffer
}

int main(int argc, char *argv[])
{
  overflow_function(argv[1]);
  exit(0);
}
