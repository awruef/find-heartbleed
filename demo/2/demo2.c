#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>

int data_array[] = { 0, 18, 21, 95, 43, 32, 51};

int main(int argc, char *argv[]) {
  int   fd;
  char  buf[512] = {0};

  fd = open("dtin", O_RDONLY);

  if(fd != -1) {
    int size;
    int res;

    res = read(fd, &size, sizeof(int));

    if(res == sizeof(int)) {
      size = ntohl(size);

      if(size < sizeof(data_array)) {
        memcpy(buf, data_array, size);
      }
      //memcpy(buf, data_array, size);
    }

    close(fd);
  }

  return 0;
}
