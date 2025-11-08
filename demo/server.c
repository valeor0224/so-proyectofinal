#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define PAGE_SIZE 256
#define NUM_PAGES 4

// Estructura de memoria simulada
char memory[NUM_PAGES][PAGE_SIZE];
int valid[NUM_PAGES]; // 1 = válida (local), 0 = migrada/inválida

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};

    // Inicializar las páginas con datos
    for (int i = 0; i < NUM_PAGES; i++) {
        snprintf(memory[i], PAGE_SIZE, "Contenido inicial de la pagina %d", i);
        valid[i] = 1;
    }

    // Crear el socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Error al crear socket");
        exit(EXIT_FAILURE);
    }

    // Permitir reutilizar puerto
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("Error en setsockopt");
        exit(EXIT_FAILURE);
    }

    // Configurar dirección
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Asociar el socket al puerto
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Error en bind");
        exit(EXIT_FAILURE);
    }

    // Escuchar conexiones
    if (listen(server_fd, 3) < 0) {
        perror("Error en listen");
        exit(EXIT_FAILURE);
    }

    printf("Servidor (Dueño DSM) esperando conexiones en el puerto %d...\n", PORT);

    // Aceptar conexión del cliente
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
        perror("Error en accept");
        exit(EXIT_FAILURE);
    }

    printf("Cliente DSM conectado.\n");

    // Bucle de atención al cliente
    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int valread = read(new_socket, buffer, sizeof(buffer) - 1);
        if (valread <= 0)
            break;

        // Interpretar el mensaje recibido
        if (strncmp(buffer, "GET", 3) == 0) {
            int page = atoi(buffer + 4);
            if (page >= 0 && page < NUM_PAGES) {
                printf("[Servidor] Solicitud de lectura de la página %d\n", page);

                // Invalidar la copia local (simula migración)
                valid[page] = 0;
                printf("[Servidor] La página %d migra del Proceso 1 al Proceso 2 (lectura)\n", page);

                // Enviar contenido al cliente
                send(new_socket, memory[page], strlen(memory[page]), 0);
                printf("[Servidor] Página %d enviada al cliente.\n", page);
            } else {
                char *msg = "ERROR: Página no válida";
                send(new_socket, msg, strlen(msg), 0);
            }
        }
        else if (strncmp(buffer, "WRITE", 5) == 0) {
            int page = atoi(buffer + 6);
            if (page >= 0 && page < NUM_PAGES) {
                printf("[Servidor] Solicitud de escritura en la página %d\n", page);
                printf("[Servidor] Invalidando copias y transfiriendo permiso de escritura.\n");

                // Invalidar la página local
                valid[page] = 0;

                // Enviar permiso al cliente
                char *ok = "OK_WRITE";
                send(new_socket, ok, strlen(ok), 0);
            } else {
                char *msg = "ERROR: Página no válida";
                send(new_socket, msg, strlen(msg), 0);
            }
        }
        else {
            printf("[Servidor] Mensaje desconocido: %s\n", buffer);
        }
    }

    printf("Cliente desconectado. Cerrando servidor.\n");
    close(new_socket);
    close(server_fd);
    return 0;
}
