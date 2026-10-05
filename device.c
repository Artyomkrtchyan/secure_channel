#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#define HS_PORT 6000
#define TAG_LEN 16
#define BUF_SIZE 70000

static int role;
static const char *LAN_IF, *WAN_IF, *MY_IP, *PEER_IP;
static uint32_t MY_PREFIX, PEER_PREFIX;
static uint8_t key[32];
static uint64_t send_ctr = 0;  
static uint64_t recv_ctr = 0;   

/* ---------------- helpers ---------------- */
static void die(const char *msg) { perror(msg); exit(1); }

static void read_exact(int fd, uint8_t *buf, int n) {
    int got = 0;
    while (got < n) {
        int r = read(fd, buf + got, n - got);
        if (r <= 0) { fprintf(stderr, "handshake: connection closed\n"); exit(1); }
        got += r;
    }
}

static void write_all(int fd, const uint8_t *buf, int n) {
    int sent = 0;
    while (sent < n) {
        int w = write(fd, buf + sent, n - sent);
        if (w <= 0) die("write");
        sent += w;
    }
}

/* ---------------- Diffie-Hellman ---------------- */
static void handshake(void) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_get_rfc3526_prime_2048(NULL);
    BIGNUM *g = BN_new();
    BIGNUM *priv = BN_new(), *pub = BN_new(), *peer = BN_new(), *shared = BN_new();
    BIGNUM *one = BN_new(), *pm1 = BN_new();
    uint8_t mybuf[256], peerbuf[256], sharedbuf[256];
    int fd;

    BN_set_word(g, 2);
    BN_set_word(one, 1);
    BN_sub(pm1, p, one);                     
    BN_rand(priv, 512, -1, 0);               
    BN_mod_exp(pub, g, priv, p, ctx);         
    BN_bn2binpad(pub, mybuf, 256);

    if (role == 1) {                         
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_port = htons(HS_PORT);
        inet_pton(AF_INET, PEER_IP, &a.sin_addr);
        while (1) {
            fd = socket(AF_INET, SOCK_STREAM, 0);
            if (connect(fd, (struct sockaddr *)&a, sizeof a) == 0) break;
            close(fd);
            sleep(1);
        }
    } else {                                  
        struct sockaddr_in a;
        int one_opt = 1;
        int srv = socket(AF_INET, SOCK_STREAM, 0);
        setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one_opt, sizeof one_opt);
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_port = htons(HS_PORT);
        inet_pton(AF_INET, MY_IP, &a.sin_addr);
        if (bind(srv, (struct sockaddr *)&a, sizeof a) < 0) die("bind");
        listen(srv, 1);
        printf("Waiting for Device1...\n");
        fd = accept(srv, NULL, NULL);
        if (fd < 0) die("accept");
        close(srv);
    }

    write_all(fd, mybuf, 256);
    read_exact(fd, peerbuf, 256);
    close(fd);

    BN_bin2bn(peerbuf, 256, peer);
    if (BN_cmp(peer, one) <= 0 || BN_cmp(peer, pm1) >= 0) {
        fprintf(stderr, "bad public value\n");
        exit(1);
    }
    BN_mod_exp(shared, peer, priv, p, ctx);  
    BN_bn2binpad(shared, sharedbuf, 256);

    /* AES key = SHA-256(shared secret) */
    EVP_Digest(sharedbuf, 256, key, NULL, EVP_sha256(), NULL);

    BN_clear_free(priv);
    BN_free(p); BN_free(g); BN_free(pub); BN_free(peer);
    BN_free(shared); BN_free(one); BN_free(pm1);
    BN_CTX_free(ctx);
}

/* ---------------- AES-256-GCM ---------------- */
static void make_nonce(uint8_t nonce[12], uint32_t prefix, uint64_t ctr) {
    int i;
    nonce[0] = prefix >> 24; nonce[1] = prefix >> 16;
    nonce[2] = prefix >> 8;  nonce[3] = prefix;
    for (i = 0; i < 8; i++) nonce[4 + i] = ctr >> (56 - 8 * i);
}

/* out gets ciphertext (len bytes), tag gets 16 bytes. returns 1 = ok */
static int gcm_encrypt(const uint8_t *nonce, const uint8_t *aad, int aad_len,
                       const uint8_t *in, int len, uint8_t *out, uint8_t *tag) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int outl, ok = 1;
    ok &= EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL);
    ok &= EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    ok &= EVP_EncryptInit_ex(c, NULL, NULL, key, nonce);
    ok &= EVP_EncryptUpdate(c, NULL, &outl, aad, aad_len);   
    ok &= EVP_EncryptUpdate(c, out, &outl, in, len);
    ok &= EVP_EncryptFinal_ex(c, out + outl, &outl);
    ok &= EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
    EVP_CIPHER_CTX_free(c);
    return ok;
}


static int gcm_decrypt(const uint8_t *nonce, const uint8_t *aad, int aad_len,
                       const uint8_t *in, int len, const uint8_t *tag, uint8_t *out) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int outl, ok = 1;
    uint8_t tagcopy[TAG_LEN];
    memcpy(tagcopy, tag, TAG_LEN);
    ok &= EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL);
    ok &= EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    ok &= EVP_DecryptInit_ex(c, NULL, NULL, key, nonce);
    ok &= EVP_DecryptUpdate(c, NULL, &outl, aad, aad_len);
    ok &= EVP_DecryptUpdate(c, out, &outl, in, len);
    ok &= EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tagcopy);
    ok &= (EVP_DecryptFinal_ex(c, out + outl, &outl) > 0);       /* checks the tag */
    EVP_CIPHER_CTX_free(c);
    return ok;
}

/* ---------------- checksums ---------------- */
static uint32_t csum_add(uint32_t sum, const uint8_t *d, int len) {
    int i;
    for (i = 0; i + 1 < len; i += 2) sum += (d[i] << 8) | d[i + 1];
    if (len & 1) sum += d[len - 1] << 8;
    return sum;
}
static uint16_t csum_end(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

static int is_pc_ip(const uint8_t *a) {
    return a[0] == 10 && ((a[1] == 10 && a[2] == 10) || (a[1] == 20 && a[2] == 20));
}

/* ---------------- main packet function ---------------- */
static int process(const uint8_t *in, int len, int encrypt, uint8_t *out) {
    if (len < 14) return 0;
    uint16_t eth_type = (in[12] << 8) | in[13];
    if (eth_type == 0x0806) {                    
        memcpy(out, in, len);
        return len;
    }
    if (eth_type != 0x0800 || len < 34) return 0;   

    const uint8_t *ip = in + 14;
    int ihl = (ip[0] & 0x0F) * 4;
    int total = (ip[2] << 8) | ip[3];
    uint8_t proto = ip[9];
    const uint8_t *src = ip + 12, *dst = ip + 16;
    if (ihl < 20 || total < ihl || total > len - 14) return 0;


    if (!encrypt && !(is_pc_ip(src) || is_pc_ip(dst))) return 0;

    if (proto != 6) {                            
        memcpy(out, in, len);
        return len;
    }

    const uint8_t *seg = ip + ihl;
    int seglen = total - ihl;
    if (seglen < 20) return 0;
    int thl = (seg[12] >> 4) * 4;
    if (thl < 20 || thl > seglen) return 0;
    const uint8_t *pl = seg + thl;
    int pllen = seglen - thl;

    /* copy Ethernet + IP + TCP headers as they are */
    memcpy(out, in, 14 + ihl + thl);
    uint8_t *oip = out + 14, *otcp = oip + ihl, *opl = otcp + thl;
    int newlen = pllen;

    if (pllen > 0) {
        uint8_t aad[16], nonce[12];
        memcpy(aad, src, 4);                     
        memcpy(aad + 4, dst, 4);
        memcpy(aad + 8, seg, 8);

        if (encrypt) {
            make_nonce(nonce, MY_PREFIX, send_ctr);
            send_ctr++;
            if (!gcm_encrypt(nonce, aad, 16, pl, pllen, opl, opl + pllen)) return 0;
            newlen = pllen + TAG_LEN;           
        } else {
            if (pllen < TAG_LEN) return 0;
            make_nonce(nonce, PEER_PREFIX, recv_ctr);
            newlen = pllen - TAG_LEN;
            if (!gcm_decrypt(nonce, aad, 16, pl, newlen, pl + newlen, opl)) {
                printf("Bad tag -> packet dropped\n");
                return 0;
            }
            recv_ctr++;
        }
    }

    /* fix IP length + checksum */
    int new_total = ihl + thl + newlen;
    oip[2] = new_total >> 8; oip[3] = new_total & 0xFF;
    oip[10] = oip[11] = 0;
    uint16_t c = csum_end(csum_add(0, oip, ihl));
    oip[10] = c >> 8; oip[11] = c & 0xFF;

    /* fix TCP checksum (pseudo header + header + payload) */
    uint8_t pseudo[12];
    int tcp_len = thl + newlen;
    memcpy(pseudo, src, 4);
    memcpy(pseudo + 4, dst, 4);
    pseudo[8] = 0; pseudo[9] = 6;
    pseudo[10] = tcp_len >> 8; pseudo[11] = tcp_len & 0xFF;
    otcp[16] = otcp[17] = 0;
    uint32_t s = csum_add(0, pseudo, 12);
    s = csum_add(s, otcp, tcp_len);             
    c = csum_end(s);
    otcp[16] = c >> 8; otcp[17] = c & 0xFF;

    return 14 + new_total;
}

/* ---------------- raw socket on one interface ---------------- */
static int open_raw(const char *ifname) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) die("socket(AF_PACKET)");
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof sll);
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_nametoindex(ifname);
    if (sll.sll_ifindex == 0) die("if_nametoindex");
    if (bind(fd, (struct sockaddr *)&sll, sizeof sll) < 0) die("bind raw");
    return fd;
}

int main(int argc, char **argv) {
    if (argc != 2 || (argv[1][0] != '1' && argv[1][0] != '2')) {
        fprintf(stderr, "usage: %s 1|2\n", argv[0]);
        return 1;
    }
    role = argv[1][0] - '0';
    if (role == 1) {
        LAN_IF = "d1_lan"; WAN_IF = "d1_wan";
        MY_IP = "172.16.0.1"; PEER_IP = "172.16.0.2";
        MY_PREFIX = 1; PEER_PREFIX = 2;
    } else {
        LAN_IF = "d2_lan"; WAN_IF = "d2_wan";
        MY_IP = "172.16.0.2"; PEER_IP = "172.16.0.1";
        MY_PREFIX = 2; PEER_PREFIX = 1;
    }

    printf("Doing DH handshake...\n");
    handshake();
    printf("Session key ready. Forwarding packets.\n");

    int lan = open_raw(LAN_IF);
    int wan = open_raw(WAN_IF);
    static uint8_t frame[BUF_SIZE], out[BUF_SIZE];
    struct pollfd fds[2] = { { lan, POLLIN, 0 }, { wan, POLLIN, 0 } };

    while (1) {
        if (poll(fds, 2, -1) < 0) {
            if (errno == EINTR) continue;
            die("poll");
        }
        for (int i = 0; i < 2; i++) {
            if (!(fds[i].revents & POLLIN)) continue;
            struct sockaddr_ll from;
            socklen_t fl = sizeof from;
            int n = recvfrom(fds[i].fd, frame, 65535, 0, (struct sockaddr *)&from, &fl);
            if (n <= 0) continue;
            if (from.sll_pkttype == PACKET_OUTGOING) continue; 

            int from_lan = (i == 0);
            int outlen = process(frame, n, from_lan, out);
            if (outlen > 0)
                send(from_lan ? wan : lan, out, outlen, 0);
        }
    }
    return 0;
}
