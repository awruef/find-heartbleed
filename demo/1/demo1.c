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
    unsigned int  selector;
    int           res;

    res = read(fd, &selector, sizeof(unsigned int));

    if(res == sizeof(unsigned int)) {
      selector = ntohl(selector);

      if(selector < sizeof(data_array)/sizeof(data_array[0])) {
        printf("%d\n", data_array[selector]);
      }

      printf("%d\n", data_array[selector]);
    }

    close(fd);
  }

  return 0;
}
