#define _GNU_SOURCE
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
    if (setresgid(0, 0, 0) != 0) return 1;
    if (setresuid(0, 0, 0) != 0) return 1;
    clearenv();

    int fd = open("/flag.txt", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 2;

    char buf[4096];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) return 3;
        if (n == 0) break;
        char *p = buf;
        while (n > 0) {
            ssize_t w = write(STDOUT_FILENO, p, (size_t)n);
            if (w <= 0) return 4;
            p += w;
            n -= w;
        }
    }
    write(STDOUT_FILENO, "\n", 1);
    return 0;
}
