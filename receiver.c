/* receiver.c   usage: ./receiver 5000 received.bin */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s port outfile\n", argv[0]); return 1; }
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(atoi(argv[1]));
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(srv, (struct sockaddr *)&a, sizeof a) < 0) { perror("bind"); return 1; }
    listen(srv, 1);
    printf("waiting...\n");
    int c = accept(srv, NULL, NULL);
    if (c < 0) { perror("accept"); return 1; }

    FILE *f = fopen(argv[2], "wb");
    if (!f) { perror("fopen"); return 1; }
    char buf[4096];
    ssize_t n;
    while ((n = recv(c, buf, sizeof buf, 0)) > 0)
        fwrite(buf, 1, n, f);
    fclose(f);
    close(c);
    printf("file received\n");
    return 0;
}
