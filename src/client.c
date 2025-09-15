// -----------------------------------------------------------------------------
// cliente.c — Cliente TCP para envío de imágenes con encabezado propio (IMGS)
//
// Resumen del protocolo (big-endian / network order):
//   Bytes 0..3   : MAGIC "IMGS"
//   Byte  4      : PROTO_VERSION (1)
//   Byte  5      : flags (bit0=1 => cliente solicita ACK del servidor)
//   Bytes 6..7   : name_len (uint16, longitud del nombre de archivo)
//   Bytes 8..15  : file_size (uint64, tamaño del archivo en bytes)
//   Bytes 16..19 : crc32 (uint32, CRC32 del archivo completo)
//   Bytes 20..   : filename (basename, 'name_len' bytes, sin NUL)
//   Luego        : payload (contenido del archivo)
//
// Flujo:
//   - El usuario ingresa rutas absolutas de imágenes (.jpg/.jpeg/.png/.gif).
//   - Por cada imagen, el cliente abre conexión TCP, envía encabezado + payload.
//   - Si expect_ack=1, el cliente espera una respuesta corta (p. ej. "OK\n")
//     hasta ack_timeout_ms. Si no llega, registra el hecho y continúa.
//   - Termina al recibir la palabra "EXIT" (exacta, mayúsculas).
//
// Notas técnicas:
//   - Endianness: los enteros multibyte en el encabezado viajan en network order.
//   - Integridad: se calcula CRC32 (polinomio 0xEDB88320) sobre el archivo.
//   - Robustez: envío por bloques (READ_CHUNK), reintentos ante EINTR,
//               y cierre ordenado de sockets.
//
// -----------------------------------------------------------------------------

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// Constantes de protocolo y parámetros operativos
#define MAGIC "IMGS"
#define PROTO_VERSION 1
#define MAX_NAME 255           // Longitud máxima aceptada para el basename
#define READ_CHUNK 65536       // Tamaño de bloque para leer/enviar archivo

// Configuración del cliente: direccionamiento y política de ACK
typedef struct {
    char server_ip[256];       // IP del servidor (o hostname si se permite DNS)
    char server_port[8];       // Puerto en texto (para getaddrinfo)
    int  expect_ack;           // 1: leer ACK; 0: no esperar ACK
    int  ack_timeout_ms;       // Tiempo máximo de espera de ACK (ms)
} client_config_t;

/* ========================== Utilidades generales ========================== */

// Salida con error formateado; útil para abortos (no usada en el flujo normal)
static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(EXIT_FAILURE);
}

// Aviso en stderr sin abortar
static void warnx(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

// Recorta espacios/blancos de extremos y normaliza CR/LF
static void trim(char *s) {
    if (!s) return;
    size_t n = strlen(s);
    while (n && (s[n-1]=='\n' || s[n-1]=='\r' || s[n-1]==' ' || s[n-1]=='\t')) s[--n] = 0;
    size_t i = 0;
    while (s[i]==' ' || s[i]=='\t') i++;
    if (i) memmove(s, s+i, strlen(s+i)+1);
}

// Comparación sufijo case-insensitive (para extensiones)
static bool ends_with_ci(const char *s, const char *suf) {
    size_t n = strlen(s), m = strlen(suf);
    if (m > n) return false;
    for (size_t i=0; i<m; i++) {
        char a = s[n-m+i], b = suf[i];
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return false;
    }
    return true;
}

// Extensiones soportadas: filtro básico para formatos habituales
static bool is_supported_image(const char *path) {
    return ends_with_ci(path, ".jpg") || ends_with_ci(path, ".jpeg")
        || ends_with_ci(path, ".png") || ends_with_ci(path, ".gif");
}

// Extrae el basename de una ruta POSIX
static const char* basename_c(const char* path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

// Conversión 64-bit host<->network (no estándar en todas las libc)
static uint64_t htonll(uint64_t v) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return (((uint64_t)htonl((uint32_t)(v & 0xFFFFFFFFULL))) << 32) | htonl((uint32_t)(v >> 32));
#else
    return v;
#endif
}

// Definida por simetría; no se usa porque solo enviamos -> htonll
static uint64_t ntohll(uint64_t v) { return htonll(v); }

/* ============================== CRC32 (IETF) ============================== */

// CRC32 incremental (polinomio reflejado 0xEDB88320)
static uint32_t crc32_update(uint32_t crc, const unsigned char *buf, size_t len) {
    crc = ~crc;
    for (size_t i=0; i<len; i++) {
        crc ^= buf[i];
        for (int k=0; k<8; k++) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

// Calcula CRC32 y tamaño total del archivo leyendo por bloques
static int crc32_file(const char *path, uint64_t *out_size, uint32_t *out_crc) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    unsigned char *buf = malloc(READ_CHUNK);
    if (!buf) { fclose(f); return -1; }
    uint32_t crc = 0; uint64_t total = 0;
    size_t n;
    while ((n = fread(buf, 1, READ_CHUNK, f)) > 0) {
        crc = crc32_update(crc, buf, n);
        total += n;
    }
    int err = ferror(f);
    fclose(f);
    free(buf);
    if (err) return -1;
    *out_size = total; *out_crc = crc;
    return 0;
}

/* ============================ Configuración I/O =========================== */

// Valores por defecto razonables para pruebas locales
static void config_default(client_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    strcpy(cfg->server_ip, "127.0.0.1");
    strcpy(cfg->server_port, "1717");
    cfg->expect_ack = 1;          // por ejemplo, pedir ACK en pruebas
    cfg->ack_timeout_ms = 3000;   // 3 s
}

// Parser simple de líneas "clave=valor" (sin secciones/escapes)
static int parse_kv(const char *line, char *k, size_t ks, char *v, size_t vs) {
    const char *eq = strchr(line, '=');
    if (!eq) return -1;
    size_t kl = (size_t)(eq - line);
    size_t vl = strlen(eq + 1);
    if (kl >= ks || vl >= vs) return -1;
    memcpy(k, line, kl); k[kl] = 0;
    memcpy(v, eq + 1, vl); v[vl] = 0;
    trim(k); trim(v);
    return 0;
}

// Carga configuración desde archivo .conf (si existe); si no, usa defaults
static void load_config(const char *path, client_config_t *cfg) {
    config_default(cfg);
    FILE *f = fopen(path, "r");
    if (!f) {
        warnx("Aviso: no se pudo abrir config '%s', usando valores por defecto.", path);
        return;
    }
    char *line = NULL; size_t cap = 0;
    while (getline(&line, &cap, f) != -1) {
        trim(line);
        if (!line[0] || line[0]=='#' || line[0]==';') continue;
        char k[128], v[256];
        if (parse_kv(line, k, sizeof k, v, sizeof v) == 0) {
            if (!strcmp(k, "server_ip")) {
                // Copia segura truncando; v debe caber en server_ip
                strncpy(cfg->server_ip, v, sizeof(cfg->server_ip)-1);
                cfg->server_ip[sizeof(cfg->server_ip)-1] = '\0';
            } else if (!strcmp(k, "server_port")) {
                strncpy(cfg->server_port, v, sizeof(cfg->server_port)-1);
                cfg->server_port[sizeof(cfg->server_port)-1] = '\0';
            } else if (!strcmp(k, "expect_ack")) {
                cfg->expect_ack = atoi(v) ? 1 : 0;
            } else if (!strcmp(k, "ack_timeout_ms")) {
                cfg->ack_timeout_ms = atoi(v);
            } else {
                warnx("Config desconocida: %s", k);
            }
        }
    }
    free(line);
    fclose(f);
}

/* ============================ Utilidades de red =========================== */

// Resuelve y conecta TCP (IPv4/IPv6). Devuelve fd o -1 en error.
static int connect_tcp(const char *ip, const char *port) {
    struct addrinfo hints, *res = NULL, *rp = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    // Si solo se admiten direcciones numéricas, añadir AI_NUMERICHOST.
    if (getaddrinfo(ip, port, &hints, &res) != 0) return -1;

    int sock = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1) continue;
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(sock); sock = -1;
    }
    freeaddrinfo(res);
    return sock;
}

// Envía exactamente len bytes (maneja cortes/retornos parciales)
static int send_all(int fd, const void *buf, size_t len) {
    const unsigned char *p = (const unsigned char*)buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, p + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

/* ============================= Encabezado IMGS ============================ */

// Construye y envía el encabezado: valida longitudes, codifica en network order
static int send_header(int sock, const char *fname, uint64_t file_size, uint32_t crc, int expect_ack) {
    size_t name_len = strnlen(fname, MAX_NAME);
    if (name_len == 0 || name_len > MAX_NAME) {
        errno = EINVAL;
        return -1;
    }
    unsigned char hdr[20 + MAX_NAME];
    memset(hdr, 0, sizeof hdr);

    // Campos fijos y de control
    memcpy(hdr, MAGIC, 4);
    hdr[4] = PROTO_VERSION;
    hdr[5] = expect_ack ? 0x01 : 0x00;

    // name_len (uint16, BE), file_size (uint64, BE), crc32 (uint32, BE)
    uint16_t nlen = htons((uint16_t)name_len);
    memcpy(hdr + 6, &nlen, 2);

    uint64_t fs_be = htonll(file_size);
    memcpy(hdr + 8, &fs_be, 8);

    uint32_t crc_be = htonl(crc);
    memcpy(hdr + 16, &crc_be, 4);

    // Nombre de archivo (bytes crudos, sin terminador NUL)
    memcpy(hdr + 20, fname, name_len);

    return send_all(sock, hdr, 20 + name_len);
}

/* ============================= Envío de payload =========================== */

// Envía el contenido del archivo por bloques grandes (eficiente y robusto)
static int send_file_payload(int sock, const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    unsigned char *buf = malloc(READ_CHUNK);
    if (!buf) { close(fd); errno = ENOMEM; return -1; }

    for (;;) {
        ssize_t n = read(fd, buf, READ_CHUNK);
        if (n < 0) {
            if (errno == EINTR) continue;
            free(buf); close(fd); return -1;
        }
        if (n == 0) break; // EOF
        if (send_all(sock, buf, (size_t)n) != 0) {
            free(buf); close(fd); return -1;
        }
    }
    free(buf); close(fd);
    return 0;
}

/* ============================ Lectura de ACK opcional ===================== */

// Si expect_ack=1, espera lectura con timeout de ack_timeout_ms y muestra respuesta
static void maybe_read_ack(int sock, int timeout_ms) {
    struct pollfd pfd = { .fd = sock, .events = POLLIN };
    int pr = poll(&pfd, 1, timeout_ms);
    if (pr <= 0) {
        printf("ACK: (no recibido dentro de %d ms, continuando)\n", timeout_ms);
        return;
    }
    char buf[256];
    ssize_t n = recv(sock, buf, sizeof(buf)-1, 0);
    if (n <= 0) {
        printf("ACK: (conexión cerrada sin respuesta)\n");
        return;
    }
    buf[n] = 0;
    trim(buf);
    printf("ACK del servidor: %s\n", buf);
}

/* ================================ UI / Main =============================== */

// Mensaje inicial de ayuda/uso en la consola
static void print_header(void) {
    printf("=== CE4303 Cliente de envío de imágenes (TCP) ===\n");
    printf("Escriba la ruta ABSOLUTA del archivo a enviar.\n");
    printf("Para terminar, escriba exactamente: EXIT\n");
}

int main(int argc, char **argv) {
    // Ruta del archivo de configuración (si se pasa con -c)
    const char *cfg_path = "etc/client.conf";
    if (argc == 3 && strcmp(argv[1], "-c")==0) {
        cfg_path = argv[2];
    } else if (argc != 1 && !(argc==3 && !strcmp(argv[1], "-c"))) {
        fprintf(stderr, "Uso: %s [-c etc/client.conf]\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Evita terminar por SIGPIPE si el peer cierra abruptamente
    signal(SIGPIPE, SIG_IGN);

    // Carga configuración (desde archivo o defaults)
    client_config_t cfg;
    load_config(cfg_path, &cfg);

    print_header();
    printf("Servidor: %s:%s  | Esperar ACK: %s  | timeout: %d ms\n",
           cfg.server_ip, cfg.server_port, cfg.expect_ack ? "sí" : "no", cfg.ack_timeout_ms);

    // Bucle interactivo principal: enviar 0..N imágenes hasta "EXIT"
    char *line = NULL; size_t cap = 0;
    for (;;) {
        printf("\nRuta de la imagen (o EXIT): ");
        fflush(stdout);
        ssize_t r = getline(&line, &cap, stdin);
        if (r < 0) {
            printf("\nEntrada finalizada.\n");
            break;
        }
        trim(line);

        // Condición de término: exactamente "EXIT" (mayúsculas)
        if (!strcmp(line, "EXIT")) {
            printf("Saliendo por orden del usuario.\n");
            break;
        }

        // Validaciones previas a la transferencia
        if (!line[0]) { warnx("Debe ingresar una ruta."); continue; }
        if (line[0] != '/') { warnx("Debe ingresar una RUTA ABSOLUTA (empieza con '/')."); continue; }
        if (!is_supported_image(line)) {
            warnx("Extensión no soportada. Use .jpg, .jpeg, .png o .gif");
            continue;
        }

        // Verifica existencia/regularidad del archivo
        struct stat st;
        if (stat(line, &st) != 0 || !S_ISREG(st.st_mode)) {
            warnx("No se puede acceder al archivo: %s", strerror(errno));
            continue;
        }

        // Cálculo de metadatos: tamaño y CRC32
        uint64_t fsize = 0; uint32_t crc = 0;
        if (crc32_file(line, &fsize, &crc) != 0) {
            warnx("Error calculando CRC32 del archivo.");
            continue;
        }

        // Obtiene basename y valida longitud para el encabezado
        const char *fname = basename_c(line);
        size_t fname_len = strlen(fname);
        if (fname_len == 0 || fname_len > MAX_NAME) {
            warnx("Nombre de archivo inválido o demasiado largo (max %d).", MAX_NAME);
            continue;
        }

        // Conexión TCP por imagen (una conexión por envío: simple y robusto)
        int sock = connect_tcp(cfg.server_ip, cfg.server_port);
        if (sock < 0) {
            warnx("No se pudo conectar con %s:%s", cfg.server_ip, cfg.server_port);
            continue;
        }

        printf("Conectado. Enviando '%s' (%" PRIu64 " bytes, CRC32=0x%08X)...\n", fname, fsize, crc);

        // Encabezado + payload
        if (send_header(sock, fname, fsize, crc, cfg.expect_ack) != 0) {
            warnx("Fallo al enviar encabezado: %s", strerror(errno));
            close(sock);
            continue;
        }
        if (send_file_payload(sock, line) != 0) {
            warnx("Fallo al enviar contenido: %s", strerror(errno));
            close(sock);
            continue;
        }
        printf("Archivo enviado correctamente.\n");

        // Si procede, esperar ACK con timeout acotado
        if (cfg.expect_ack) {
            maybe_read_ack(sock, cfg.ack_timeout_ms);
        }

        close(sock);
    }

    free(line);
    return 0;
}
