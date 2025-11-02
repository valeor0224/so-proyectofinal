/* mini_dsm.c
   Mini DSM por páginas (2 nodos).
   Uso:
     Terminal A: ./mini_dsm owner <port>
     Terminal B: ./mini_dsm peer  <host> <port>
   (owner inicia servidor TCP en <port>; peer conecta)
*/
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/ucontext.h>
#include <fcntl.h>
#include <sys/time.h>

#define N_PAGES 16
#define PAGE_BITS 12
#define PAGE_SIZE 4096  // asumimos 4KB (posible usar getpagesize())
#define REGION_SIZE (N_PAGES * PAGE_SIZE)

/* Estados de página local */
typedef enum { ST_INVALID=0, ST_READ, ST_OWNER } page_state_t;

/* Mensajes (tipos simples de 1 byte) */
enum {
    MSG_REQ_READ = 1,
    MSG_REQ_EXCL = 2,
    MSG_SEND_PAGE = 3,
    MSG_INVALIDATE = 4,
    MSG_INVAL_ACK = 5
};

struct msg_hdr {
    uint8_t type;
    uint8_t page_idx;
};

/* Variables globales por simplicidad */
static void *region = NULL;
static page_state_t page_state[N_PAGES];
static int peer_fd = -1;
static bool am_owner_initial = false;
static int my_id = 0; // 0 owner, 1 peer

/* util: send all */
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

/* enviar page (payload) */
static int send_page(int fd, uint8_t page_idx) {
    struct msg_hdr h = {MSG_SEND_PAGE, page_idx};
    if (send_all(fd, &h, sizeof(h)) < 0) return -1;
    void *src = region + (page_idx * PAGE_SIZE);
    if (send_all(fd, src, PAGE_SIZE) < 0) return -1;
    return 0;
}

/* procesar solicitudes entrantes (bucle simple, no-threaded). Retorna -1 en error */
static int process_messages_once(int fd_other) {
    struct msg_hdr h;
    ssize_t r = recv(fd_other, &h, sizeof(h), MSG_DONTWAIT);
    if (r == 0) {
        printf("[node%d] conexión cerrada por peer\n", my_id);
        return -1;
    } else if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        perror("recv header");
        return -1;
    } else if (r != sizeof(h)) {
        fprintf(stderr, "recv header corto\n");
        return -1;
    }

    uint8_t p = h.page_idx;
    if (p >= N_PAGES) {
        fprintf(stderr,"idx fuera de rango\n");
        return -1;
    }

    if (h.type == MSG_REQ_READ) {
        printf("[node%d] REQ_READ page %u\n", my_id, p);
        // Política: migramos la página: enviamos y marcamos INVALID localmente
        if (page_state[p] == ST_OWNER) {
            if (send_page(fd_other, p) < 0) { perror("send_page"); return -1; }
            page_state[p] = ST_INVALID;
            mprotect(region + p*PAGE_SIZE, PAGE_SIZE, PROT_NONE);
            printf("[node%d] migró page %u -> peer, ahora INVALID\n", my_id, p);
        } else {
            // no soy owner: no tengo; responder con cero? (simplificamos: ignorar)
            printf("[node%d] no owner de page %u (REQ_READ)\n", my_id, p);
        }
    } else if (h.type == MSG_REQ_EXCL) {
        printf("[node%d] REQ_EXCL page %u\n", my_id, p);
        // invalidar mi copia si la tengo
        if (page_state[p] == ST_READ) {
            page_state[p] = ST_INVALID;
            mprotect(region + p*PAGE_SIZE, PAGE_SIZE, PROT_NONE);
            // enviar ack
            struct msg_hdr ack = {MSG_INVAL_ACK, p};
            send_all(fd_other, &ack, sizeof(ack));
            printf("[node%d] invalidé mi copia de %u y envié INVAL_ACK\n", my_id, p);
        }
        // si soy owner: enviar page y transferir ownership
        if (page_state[p] == ST_OWNER) {
            if (send_page(fd_other, p) < 0) { perror("send_page"); return -1; }
            page_state[p] = ST_INVALID;
            mprotect(region + p*PAGE_SIZE, PAGE_SIZE, PROT_NONE);
            printf("[node%d] transferí propiedad de %u a requester\n", my_id, p);
        }
    } else if (h.type == MSG_SEND_PAGE) {
        // recibir payload
        printf("[node%d] esperando payload de page %u\n", my_id, p);
        if (recv_all(fd_other, region + p*PAGE_SIZE, PAGE_SIZE) < 0) { perror("recv payload"); return -1; }
        // por defecto instalamos como READ (si fue por REQ_READ) o OWNER si pedimos exclusión
        // Para simplificar, si recibimos SEND_PAGE sin otra señal, instalamos como READ.
        page_state[p] = ST_READ;
        mprotect(region + p*PAGE_SIZE, PAGE_SIZE, PROT_READ);
        printf("[node%d] instalé page %u (READ)\n", my_id, p);
    } else if (h.type == MSG_INVALIDATE) {
        printf("[node%d] received INVALIDATE for page %u\n", my_id, p);
        if (page_state[p] != ST_INVALID) {
            page_state[p] = ST_INVALID;
            mprotect(region + p*PAGE_SIZE, PAGE_SIZE, PROT_NONE);
        }
        // ack
        struct msg_hdr ack = {MSG_INVAL_ACK, p};
        send_all(fd_other, &ack, sizeof(ack));
    } else if (h.type == MSG_INVAL_ACK) {
        printf("[node%d] received INVAL_ACK for page %u\n", my_id, p);
        // nothing further here in this simple flow
    } else {
        printf("[node%d] msg tipo desconocido %d\n", my_id, h.type);
    }
    return 0;
}

/* send REQ_READ */
static int send_req_read(int fd, uint8_t p) {
    struct msg_hdr h = {MSG_REQ_READ, p};
    return send_all(fd, &h, sizeof(h)) == sizeof(h) ? 0 : -1;
}
static int send_req_excl(int fd, uint8_t p) {
    struct msg_hdr h = {MSG_REQ_EXCL, p};
    return send_all(fd, &h, sizeof(h)) == sizeof(h) ? 0 : -1;
}

/* SIGSEGV handler: intenta obtener página por red si es inválida */
static void segv_handler(int sig, siginfo_t *si, void *unused) {
    void *addr = si->si_addr;
    uintptr_t base = (uintptr_t)region;
    uintptr_t a = (uintptr_t)addr;
    if (a < base || a >= base + REGION_SIZE) {
        // no es nuestro region: reinstalar default y re-lanzar
        signal(SIGSEGV, SIG_DFL);
        raise(SIGSEGV);
        return;
    }
    size_t offset = a - base;
    uint8_t pidx = offset / PAGE_SIZE;
    printf("[node%d] SIGSEGV en addr %p page %u (estado local=%d)\n", my_id, addr, pidx, page_state[pidx]);

    if (page_state[pidx] == ST_INVALID) {
        // solicitamos lectura al peer (asumimos peer es dueño inicial si my_id==1)
        if (peer_fd < 0) { fprintf(stderr,"no hay peer_fd\n"); exit(1); }
        // Si queremos escribir (si la instrucción que causó SIGSEGV era escritura), sería ideal detectar; simplificamos:
        // Primero pedimos READ (migración). Si el proceso luego escribe, pedirá EXCL (otro fault).
        if (send_req_read(peer_fd, pidx) < 0) { perror("send_req_read"); exit(1); }

        // Esperamos recibir SEND_PAGE (bloqueante)
        // La recepción real es hecha por process_messages_once en el bucle principal; para simplicidad, bloqueamos aquí:
        struct msg_hdr h;
        if (recv_all(peer_fd, &h, sizeof(h)) < 0) { perror("recv hdr in handler"); exit(1); }
        if (h.type == MSG_SEND_PAGE && h.page_idx == pidx) {
            if (recv_all(peer_fd, region + pidx*PAGE_SIZE, PAGE_SIZE) < 0) { perror("recv payload in handler"); exit(1); }
            page_state[pidx] = ST_READ;
            if (mprotect(region + pidx*PAGE_SIZE, PAGE_SIZE, PROT_READ) != 0) perror("mprotect install read");
            printf("[node%d] handler instaló page %u (READ).\n", my_id, pidx);
            return; // volver al programa (reintento de instrucción)
        } else {
            fprintf(stderr,"esperaba SEND_PAGE en handler\n");
            exit(1);
        }
    } else if (page_state[pidx] == ST_READ) {
        // acceso por escritura a página de solo lectura -> pedir exclusión
        printf("[node%d] intento escribir page %u; pido EXCL\n", my_id, pidx);
        if (send_req_excl(peer_fd, pidx) < 0) { perror("send_req_excl"); exit(1); }
        // esperar SEND_PAGE con payload
        struct msg_hdr h;
        if (recv_all(peer_fd, &h, sizeof(h)) < 0) { perror("recv hdr for EXCL"); exit(1); }
        if (h.type == MSG_SEND_PAGE && h.page_idx == pidx) {
            if (recv_all(peer_fd, region + pidx*PAGE_SIZE, PAGE_SIZE) < 0) { perror("recv payload excl"); exit(1); }
            page_state[pidx] = ST_OWNER;
            if (mprotect(region + pidx*PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) perror("mprotect install rw");
            printf("[node%d] handler instaló page %u (OWNER/RW).\n", my_id, pidx);
            return;
        } else {
            fprintf(stderr,"esperaba SEND_PAGE tras EXCL\n");
            exit(1);
        }
    } else {
        fprintf(stderr,"estado inesperado en handler: %d\n", page_state[pidx]);
        exit(1);
    }
}

/* setup region y handler */
static void setup_region_and_handler(bool owner_initial) {
    region = mmap(NULL, REGION_SIZE, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (region == MAP_FAILED) { perror("mmap"); exit(1); }
    for (int i=0;i<N_PAGES;i++) page_state[i] = ST_INVALID;

    if (owner_initial) {
        for (int i=0;i<N_PAGES;i++) {
            page_state[i] = ST_OWNER;
            // inicializar contenido (por ejemplo, llenar con números)
            char *p = (char*)region + i*PAGE_SIZE;
            // temporarily allow write to init
            if (mprotect(p, PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) perror("mprotect init");
            memset(p, (char)('A'+(i%26)), PAGE_SIZE);
            if (mprotect(p, PAGE_SIZE, PROT_NONE) != 0) perror("mprotect post-init"); // owner will set PROT_NONE to trigger migration on access
            // note: marking owner pages as PROT_NONE simula que solo owner sabe tener contenido; owner will mprotect when needed.
        }
    }

    // instalamos handler SIGSEGV
    struct sigaction sa;
    sa.sa_sigaction = segv_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    if (sigaction(SIGSEGV, &sa, NULL) < 0) { perror("sigaction"); exit(1); }
}

/* helpers sockets: server accept and client connect */
static int start_server(const char *port) {
    struct addrinfo hints={}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(NULL, port, &hints, &res) != 0) { perror("getaddrinfo"); exit(1); }
    int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    int yes = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    if (bind(s, res->ai_addr, res->ai_addrlen) < 0) { perror("bind"); exit(1); }
    listen(s,1);
    printf("Esperando conexión en puerto %s...\n", port);
    int ac = accept(s, NULL, NULL);
    close(s);
    if (ac < 0) { perror("accept"); exit(1); }
    return ac;
}
static int connect_to(const char *host, const char *port) {
    struct addrinfo hints={}, *res, *p;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) { perror("getaddrinfo"); exit(1); }
    int sock = -1;
    for (p=res;p;p=p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) continue;
        if (connect(sock, p->ai_addr, p->ai_addrlen) == 0) break;
        close(sock); sock = -1;
    }
    freeaddrinfo(res);
    if (sock < 0) { fprintf(stderr,"no pude conectar\n"); exit(1); }
    return sock;
}

/* demo: función simple que lee y escribe ciertas páginas para provocar migración e invalidación */
static void demo_actions() {
    // small sleep to stabilize
    sleep(1);
    if (my_id == 0) {
        // owner initial: simplemente duerme y procesa mensajes
        printf("[node0] soy owner inicial; mostrando contenido de las primeras 2 páginas en memoria cada 2s (pero no mapeadas hasta demanda).\n");
    } else {
        // peer: intentionalmente leer page 0 then write page 0
        printf("[node1] voy a leer page 0 (provocará migración)\n");
        char buf = *((char*)(region + 0*PAGE_SIZE)); // leer primer byte -> puede causar SIGSEGV -> migración
        printf("[node1] leí byte '%c' de page 0\n", buf);
        sleep(1);
        printf("[node1] ahora intento escribir en page 0 -> provocará petición EXCL\n");
        char *p = (char*)(region + 0*PAGE_SIZE);
        p[0] = 'Z'; // escritura -> si estaba READ, handler pedirá EXCL y recibirá page con RW
        printf("[node1] escribí '%c' en page 0\n", p[0]);
    }
}

/* loop principal: procesa mensajes e invoca demo */
int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr,"Uso: %s owner <port>  OR  %s peer <host> <port>\n", argv[0], argv[0]);
        return 1;
    }
    bool owner = strcmp(argv[1], "owner")==0;
    my_id = owner ? 0 : 1;
    setup_region_and_handler(owner);

    if (owner) {
        int s = start_server(argv[2]);
        peer_fd = s;
    } else {
        peer_fd = connect_to(argv[2], argv[3]);
    }
    // non-blocking recv for processing messages asynchronously
    int flags = fcntl(peer_fd, F_GETFL, 0);
    fcntl(peer_fd, F_SETFL, flags | O_NONBLOCK);

    // run demo actions shortly after
    if (!owner) {
        // spawn a child thread-like behavior: we'll use a fork to run demo actions while parent loops processing messages.
        pid_t pid = fork();
        if (pid == 0) {
            // child: small delay to let main loop start
            sleep(1);
            demo_actions();
            exit(0);
        }
    }

    // loop principal: procesar mensajes y dormir un poco
    for (;;) {
        if (process_messages_once(peer_fd) < 0) break;
        usleep(100000); // 100ms
    }
    close(peer_fd);
    return 0;
}
