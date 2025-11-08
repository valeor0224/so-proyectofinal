#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define PAGE_SIZE 256
#define NUM_PAGES 4

// Simulación de memoria local
char memory[NUM_PAGES][PAGE_SIZE];
int valid[NUM_PAGES]; // 0 = no tengo la página, 1 = tengo copia válida

void mostrar_memoria_local() {
    printf("\n=== Estado de la memoria local ===\n");
    for (int i = 0; i < NUM_PAGES; i++) {
        printf("Página %d: %s (%s)\n",
               i,
               valid[i] ? memory[i] : "(vacía)",
               valid[i] ? "válida" : "inválida");
    }
    printf("==================================\n");
}

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};

    // Crear socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Error al crear socket");
        return 1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("Dirección inválida o no soportada");
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Error al conectar con el servidor");
        return 1;
    }

    printf("Cliente DSM conectado al servidor (dueño de las páginas)\n");

    // Inicializar memoria local vacía
    for (int i = 0; i < NUM_PAGES; ++i)
        valid[i] = 0;

    int opcion, page;
    char msg[32];

    while (1) {
        mostrar_memoria_local();
        printf("\nSelecciona una opción:\n");
        printf("1. Leer página\n");
        printf("2. Escribir página\n");
        printf("3. Salir\n");
        printf("> ");
        scanf("%d", &opcion);

        if (opcion == 3) {
            printf("Saliendo del cliente DSM...\n");
            break;
        }

        printf("Número de página (0-%d): ", NUM_PAGES - 1);
        scanf("%d", &page);

        if (page < 0 || page >= NUM_PAGES) {
            printf("Página no válida.\n");
            continue;
        }

        if (opcion == 1) { // Leer página
            printf("\n[Cliente] Intentando leer página %d...\n", page);
            if (!valid[page]) {
                sprintf(msg, "GET %d", page);
                send(sock, msg, strlen(msg), 0);

                memset(buffer, 0, sizeof(buffer));
                int valread = read(sock, buffer, sizeof(buffer) - 1);
                if (valread > 0) {
                    strncpy(memory[page], buffer, PAGE_SIZE - 1);
                    valid[page] = 1;
                    printf("[Cliente] Página %d recibida: \"%s\"\n", page, memory[page]);
                } else {
                    printf("Error al recibir página.\n");
                }
            } else {
                printf("[Cliente] Ya tengo la página %d localmente.\n", page);
            }
        }
        else if (opcion == 2) { // Escribir página
            printf("\n[Cliente] Solicitando permiso de escritura para página %d...\n", page);
            sprintf(msg, "WRITE %d", page);
            send(sock, msg, strlen(msg), 0);

            memset(buffer, 0, sizeof(buffer));
            int valread = read(sock, buffer, sizeof(buffer) - 1);
            if (valread > 0 && strstr(buffer, "OK_WRITE")) {
                printf("[Cliente] Permiso concedido. Ingresa nuevo contenido: ");
                getchar(); // limpiar buffer
                fgets(memory[page], PAGE_SIZE, stdin);
                memory[page][strcspn(memory[page], "\n")] = 0; // quitar salto de línea
                valid[page] = 1;
                printf("[Cliente] Página %d actualizada localmente.\n", page);
            } else {
                printf("[Cliente] Error o permiso denegado.\n");
            }
        }
    }

    close(sock);
    return 0;
}
