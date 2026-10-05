/* sender.c   usage: ./sender 10.20.20.2 5000 test.bin */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char **argv) {
    if (argc != 4) { fprintf(stderr, "usage: %s ip port file\n", argv[0]); return 1; }
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(atoi(argv[2]));
    inet_pton(AF_INET, argv[1], &a.sin_addr);
    if (connect(s, (struct sockaddr *)&a, sizeof a) < 0) { perror("Connect"); return 1; }

    FILE *f = fopen(argv[3], "rb");
    if (!f) { perror("fopen"); return 1; }
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) {
        size_t sent = 0;
        while (sent < n) {
            ssize_t w = send(s, buf + sent, n - sent, 0);
            if (w <= 0) { perror("Send"); return 1; }
            sent += w;
        }
    }
    fclose(f);
    close(s);
    printf("File sent\n");
    return 0;
}
