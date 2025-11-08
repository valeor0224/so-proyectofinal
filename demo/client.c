#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define PAGE_SIZE 256
#define NUM_PAGES 4

// Estructura de memoria local simulada
char memory[NUM_PAGES][PAGE_SIZE];
int valid[NUM_PAGES]; // 0 = no tengo la página, 1 = tengo copia válida

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};

    // Crear el socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Error al crear socket");
        return 1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Conectarse al servidor local
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

    // === Simulación de acceso a páginas ===
    int page = 2;  // Página a leer
    printf("\n[Cliente] Intentando leer página %d...\n", page);

    if (!valid[page]) {
        // No tengo la página, solicitarla al dueño
        char msg[16];
        sprintf(msg, "GET %d", page);
        send(sock, msg, strlen(msg), 0);

        // Recibir contenido
        memset(buffer, 0, sizeof(buffer));
        int valread = read(sock, buffer, sizeof(buffer) - 1);
        if (valread > 0) {
            strncpy(memory[page], buffer, PAGE_SIZE - 1);
            valid[page] = 1;
            printf("[Cliente] Página %d recibida y almacenada localmente: \"%s\"\n", page, memory[page]);
        }
    }

    // === Simulación de escritura ===
    printf("\n[Cliente] Solicitando permiso de escritura en página %d...\n", page);
    char msg[16];
    sprintf(msg, "WRITE %d", page);
    send(sock, msg, strlen(msg), 0);

    memset(buffer, 0, sizeof(buffer));
    int valread = read(sock, buffer, sizeof(buffer) - 1);
    if (valread > 0 && strstr(buffer, "OK_WRITE")) {
        printf("[Cliente] Permiso de escritura concedido por el servidor.\n");

        // Simular modificación local
        snprintf(memory[page], PAGE_SIZE, "Página %d modificada por el cliente", page);
        printf("[Cliente] Nueva versión local: \"%s\"\n", memory[page]);
    }

    printf("\n[Cliente] Fin de la simulación DSM.\n");

    close(sock);
    return 0;
}
