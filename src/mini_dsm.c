/*
 * mini_dsm_exp.c
 * Versión explicativa del mini DSM de 2 nodos
 *
 * Uso:
 *  Terminal 1: ./mini_dsm_exp owner <port>
 *  Terminal 2: ./mini_dsm_exp peer <host> <port>
 *
 * Demuestra:
 *   1. Migración de página por lectura
 *   2. Invalidación y transferencia por escritura
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/time.h>

#define N_PAGES 16
#define PAGE_SIZE 4096
#define REGION_SIZE (N_PAGES * PAGE_SIZE)

typedef enum { ST_INVALID = 0, ST_READ, ST_OWNER } page_state_t;

enum { MSG_REQ_READ = 1, MSG_REQ_EXCL = 2, MSG_SEND_PAGE = 3, MSG_INVALIDATE = 4, MSG_INVAL_ACK = 5 };

struct msg_hdr {
    uint8_t type;
    uint8_t page_idx;
};

static void *region = NULL;
static page_state_t page_state[N_PAGES];
static int peer_fd = -1;
static int my_id = 0; // 0 = owner, 1 = peer

/* ------------------- Utilidades de red ------------------- */
static ssize_t send_all(int fd, const void *buf, size_t len) {
    size_t sent = 0;
    const char *b = buf;
    while (sent < len) {
        ssize_t r = send(fd, b + sent, len - sent, 0);
        if (r <= 0) return -1;
        sent += r;
    }
    return sent;
}

static ssize_t recv_all(int fd, void *buf, size_t len) {
    size_t got = 0;
    char *b = buf;
    while (got < len) {
        ssize_t r = recv(fd, b + got, len - got, 0);
        if (r <= 0) return -1;
        got += r;
    }
    return got;
}

/* ------------------- Envío de páginas ------------------- */
static int send_page(int fd, uint8_t page_idx) {
    struct msg_hdr h = {MSG_SEND_PAGE, page_idx};
    printf("[Node%d][Protocolo] Enviando contenido de página %u al peer\n", my_id, page_idx);
    if (send_all(fd, &h, sizeof(h)) < 0) return -1;

    void *src = region + (page_idx * PAGE_SIZE);
    if (mprotect(src, PAGE_SIZE, PROT_READ) != 0) perror("mprotect temp read");
    if (send_all(fd, src, PAGE_SIZE) < 0) return -1;
    if (mprotect(src, PAGE_SIZE, PROT_NONE) != 0) perror("mprotect restore");
    return 0;
}

/* ------------------- Procesar mensajes ------------------- */
static int process_messages_once(int fd_other) {
    struct msg_hdr h;
    ssize_t r = recv(fd_other, &h, sizeof(h), MSG_DONTWAIT);
    if (r == 0) return -1;
    if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        perror("recv header");
        return -1;
    }

    uint8_t p = h.page_idx;
    switch (h.type) {
        case MSG_REQ_READ:
            printf("[Node%d][Protocolo] Recibida solicitud de lectura (REQ_READ) para página %u\n", my_id, p);
            if (page_state[p] == ST_OWNER) {
                send_page(fd_other, p);
                page_state[p] = ST_INVALID;
                mprotect(region + p * PAGE_SIZE, PAGE_SIZE, PROT_NONE);
                printf("[Node%d][Protocolo] Página %u migrada -> peer (propietario invalida su copia)\n", my_id, p);
            }
            break;

        case MSG_REQ_EXCL:
            printf("[Node%d][Protocolo] Recibida solicitud de escritura exclusiva (REQ_EXCL) para página %u\n", my_id, p);
            if (page_state[p] == ST_OWNER) {
                send_page(fd_other, p);
                page_state[p] = ST_INVALID;
                mprotect(region + p * PAGE_SIZE, PAGE_SIZE, PROT_NONE);
                printf("[Node%d][Protocolo] Propiedad de página %u transferida al peer\n", my_id, p);
            }
            break;

        case MSG_SEND_PAGE:
            printf("[Node%d][Protocolo] Recibido contenido de página %u\n", my_id, p);
            recv_all(fd_other, region + p * PAGE_SIZE, PAGE_SIZE);
            page_state[p] = ST_READ;
            mprotect(region + p * PAGE_SIZE, PAGE_SIZE, PROT_READ);
            printf("[Node%d][Memoria] Página %u instalada localmente (modo LECTURA)\n", my_id, p);
            break;

        default:
            printf("[Node%d] Mensaje desconocido tipo %d\n", my_id, h.type);
    }
    return 0;
}

/* ------------------- Handler de fallos de página ------------------- */
static void segv_handler(int sig, siginfo_t *si, void *unused) {
    void *addr = si->si_addr;
    uintptr_t base = (uintptr_t)region;
    uintptr_t a = (uintptr_t)addr;
    uint8_t page_idx = (a - base) / PAGE_SIZE;

    printf("\n[Node%d][Handler] SIGSEGV: acceso a dirección %p (página %u, estado actual=%d)\n",
           my_id, addr, page_idx, page_state[page_idx]);

    if (page_state[page_idx] == ST_INVALID) {
        struct msg_hdr req = {MSG_REQ_READ, page_idx};
        printf("[Node%d][Handler] Enviando solicitud REQ_READ al owner para página %u\n", my_id, page_idx);
        send_all(peer_fd, &req, sizeof(req));

        struct msg_hdr resp;
        recv_all(peer_fd, &resp, sizeof(resp));
        if (resp.type == MSG_SEND_PAGE) {
            void *dst = region + page_idx * PAGE_SIZE;
            mprotect(dst, PAGE_SIZE, PROT_READ | PROT_WRITE);
            recv_all(peer_fd, dst, PAGE_SIZE);
            mprotect(dst, PAGE_SIZE, PROT_READ);
            page_state[page_idx] = ST_READ;
            printf("[Node%d][Handler] Página %u instalada localmente (READ)\n", my_id, page_idx);
        }
        return;
    }

    if (page_state[page_idx] == ST_READ) {
        struct msg_hdr req = {MSG_REQ_EXCL, page_idx};
        printf("[Node%d][Handler] Enviando solicitud REQ_EXCL al owner (para escritura) página %u\n", my_id, page_idx);
        send_all(peer_fd, &req, sizeof(req));

        struct msg_hdr resp;
        recv_all(peer_fd, &resp, sizeof(resp));
        if (resp.type == MSG_SEND_PAGE) {
            void *dst = region + page_idx * PAGE_SIZE;
            mprotect(dst, PAGE_SIZE, PROT_READ | PROT_WRITE);
            recv_all(peer_fd, dst, PAGE_SIZE);
            page_state[page_idx] = ST_OWNER;
            printf("[Node%d][Handler] Página %u instalada localmente (OWNER/RW)\n", my_id, page_idx);
        }
        return;
    }

    fprintf(stderr, "[Node%d][Handler] Error: acceso inesperado en estado %d\n", my_id, page_state[page_idx]);
    exit(1);
}

/* ------------------- Inicialización ------------------- */
static void setup_region_and_handler(bool owner_initial) {
    region = mmap(NULL, REGION_SIZE, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (region == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    for (int i = 0; i < N_PAGES; i++) page_state[i] = ST_INVALID;

    if (owner_initial) {
        for (int i = 0; i < N_PAGES; i++) {
            page_state[i] = ST_OWNER;
            char *p = (char *)region + i * PAGE_SIZE;
            mprotect(p, PAGE_SIZE, PROT_READ | PROT_WRITE);
            memset(p, 'A' + (i % 26), PAGE_SIZE);
            mprotect(p, PAGE_SIZE, PROT_NONE);
        }
        printf("[Node0][Init] Dueño inicial de todas las páginas (propietario del espacio compartido)\n");
    }

    struct sigaction sa;
    sa.sa_sigaction = segv_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGSEGV, &sa, NULL);
}

/* ------------------- Red ------------------- */
static int start_server(const char *port) {
    struct addrinfo hints = {}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    getaddrinfo(NULL, port, &hints, &res);

    int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    bind(s, res->ai_addr, res->ai_addrlen);
    listen(s, 1);

    printf("[Node0][Red] Esperando conexión en puerto %s...\n", port);
    int ac = accept(s, NULL, NULL);
    close(s);
    printf("[Node0][Red] Conexión establecida con peer\n");
    return ac;
}

static int connect_to(const char *host, const char *port) {
    struct addrinfo hints = {}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    getaddrinfo(host, port, &hints, &res);

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    connect(sock, res->ai_addr, res->ai_addrlen);
    printf("[Node1][Red] Conectado al owner %s:%s\n", host, port);
    return sock;
}

/* ------------------- Demo ------------------- */
static void demo_actions() {
    sleep(1);
    printf("\n[Node1][Demo] Intentando leer página 0 (provocará migración de lectura)\n");
    char c = *((char *)(region + 0 * PAGE_SIZE));
    printf("[Node1][Demo] Leído '%c' de página 0\n", c);
    sleep(1);
    printf("\n[Node1][Demo] Intentando escribir en página 0 (provocará invalidación y transferencia de propiedad)\n");
    char *p = (char *)(region + 0 * PAGE_SIZE);
    p[0] = 'Z';
    printf("[Node1][Demo] Escrito '%c' en página 0 (ahora soy OWNER)\n", p[0]);
}

/* ------------------- Main ------------------- */
int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Uso: %s owner <port> | %s peer <host> <port>\n", argv[0], argv[0]);
        return 1;
    }

    bool owner = strcmp(argv[1], "owner") == 0;
    my_id = owner ? 0 : 1;

    setup_region_and_handler(owner);
    peer_fd = owner ? start_server(argv[2]) : connect_to(argv[2], argv[3]);

    if (!owner) {
        pid_t pid = fork();
        if (pid == 0) {
            sleep(1);
            demo_actions();
            exit(0);
        }
    }

    while (1) {
        if (process_messages_once(peer_fd) < 0) break;
        usleep(100000);
    }

    printf("\n[Node%d][Resumen Final] Estado de las primeras 4 páginas:\n", my_id);
    for (int i = 0; i < 4; i++) {
        const char *st = (page_state[i] == ST_OWNER) ? "OWNER" :
                         (page_state[i] == ST_READ)  ? "READ" : "INVALID";
        printf("  Página %d -> %s\n", i, st);
    }

    close(peer_fd);
    return 0;
}
