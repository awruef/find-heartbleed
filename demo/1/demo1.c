#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>

int data_array[] = { 0, 18, 21, 95, 43, 32, 51};

int main(int argc, char *argv[]) {
  int fd;

  fd = open("dtin", O_RDONLY);

  if(fd != -1) {
    int   data;
    int   res;

    res = read(fd, &data, sizeof(unsigned int));

    if(res == sizeof(unsigned int)) {
      data = ntohl(data);

      if(data >= 0 && data < sizeof(data_array)/sizeof(data_array[0])) {
        printf("%d\n", data_array[data]);
      } else {
        printf("%d\n", data_array[data]);
      }
    }

    close(fd);
  }

  return 0;
}
