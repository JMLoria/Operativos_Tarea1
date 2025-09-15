#define _POSIX_C_SOURCE 200809L // Enable POSIX features for portability
#include <stdio.h>              // Standard I/O functions
#include <stdlib.h>             // General utilities
#include <stdint.h>             // Integer types
#include <string.h>             // String manipulation
#include <limits.h>             // Limits of integral types
#include <errno.h>              // Error codes
#include <stdarg.h>             // Variable argument lists
#include <time.h>               // Time functions
#include <unistd.h>             // POSIX API
#include <pthread.h>            // POSIX threads
#include <signal.h>             // Signal handling
#include <endian.h>             // Endianness macros
#include <sys/socket.h>         // Socket API
#include <netinet/in.h>         // Internet address family
#include <arpa/inet.h>          // IP address conversion
#include <sys/stat.h>           // File status
#include <sys/types.h>          // Data types

// stb_image: Image loading and saving library
#define STB_IMAGE_IMPLEMENTATION
#include "etc/stb_image.h"
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "etc/stb_image_write.h"

#ifndef be64toh
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define be64toh(x) __builtin_bswap64(x)
# else
#define be64toh(x) (x)
#endif
#endif

#ifndef be32toh
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define be32toh(x) __builtin_bswap32(x) 
#else
#define be32toh(x) (x)
#endif
#endif

// Default configuration values
#define DEFAULT_PORT 1717                           // Default server port
#define DEFAULT_BASE "./imageserver_data"           // Default base directory for images
#define DEFAULT_LOG "./imageserver_data/server.log" // Default log file path
#define CONFIG_FILE "./etc/server.conf"             // Configuration file path
#define BACKLOG 10                                  // Max pending connections

// Safety limits for uploads
#define MAX_FILENAME_LEN 255                      // Maximum filename length
#define MAX_FILESIZE_BYTES (100ULL * 1024 * 1024) // 100 MB max per upload

// Global configuration variables
static int server_port = DEFAULT_PORT;
static char base_dir[PATH_MAX] = DEFAULT_BASE;
static char log_file[PATH_MAX] = DEFAULT_LOG;

// Load configuration from file (PORT, BASE_DIR, LOG_FILE)
void load_config(const char *path)
{
    FILE *f = fopen(path, "r"); // Open config file for reading
    if (!f)
    {
        // If config file can't be opened, use default values
        fprintf(stderr, "Couldn't open config file: %s, using defaults\n", path);
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), f))
    {
        char key[128], val[384];
        // Parse key=value pairs
        if (sscanf(line, "%127[^=]=%383s", key, val) == 2)
        {
            if (strcmp(key, "PORT") == 0)
                server_port = atoi(val);
            else if (strcmp(key, "BASE_DIR") == 0)
                strncpy(base_dir, val, sizeof(base_dir) - 1);
            else if (strcmp(key, "LOG_FILE") == 0)
                strncpy(log_file, val, sizeof(log_file) - 1);
        }
    }
    fclose(f);
}

// Ensure directory for a given file path exists (mimics 'mkdir -p')
static void ensure_dir_for_file(const char *filepath)
{
    char tmp[PATH_MAX];
    strncpy(tmp, filepath, sizeof(tmp) - 1);
    char *last = strrchr(tmp, '/');
    if (!last)
        return;
    *last = '\0';
    // Create each path component if needed
    char accum[PATH_MAX] = "";
    char *tok = strtok(tmp, "/");
    while (tok)
    {
        if (strlen(accum) == 0)
            snprintf(accum, sizeof(accum), "%s", tok);
        else
            snprintf(accum + strlen(accum), sizeof(accum) - strlen(accum), "/%s", tok);
        mkdir(accum, 0755);
        tok = strtok(NULL, "/");
    }
}

// Log a message to the server log file
static void logmsg(const char *client, const char *file, const char *status)
{
    // Ensure log directory exists
    ensure_dir_for_file(log_file);

    FILE *f = fopen(log_file, "a");
    if (!f)
        return;
    // Write timestamp, client IP, file, and status
    time_t t = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&t));
    fprintf(f, "[%s] Client:%s File:%s Status:%s\n", ts, client ? client : "-", file ? file : "-", status);
    fclose(f);
}

// Ensure all required base directories exist
static void ensure_dirs()
{
    mkdir(base_dir, 0755);
    char buf[PATH_MAX * 2];
    snprintf(buf, sizeof(buf), "%s/processed", base_dir);
    mkdir(buf, 0755);
    snprintf(buf, sizeof(buf), "%s/classify", base_dir);
    mkdir(buf, 0755);
    snprintf(buf, sizeof(buf), "%s/classify/rojas", base_dir);
    mkdir(buf, 0755);
    snprintf(buf, sizeof(buf), "%s/classify/verdes", base_dir);
    mkdir(buf, 0755);
    snprintf(buf, sizeof(buf), "%s/classify/azules", base_dir);
    mkdir(buf, 0755);

    // Ensure log directory exists
    ensure_dir_for_file(log_file);
}

// Perform histogram equalization on RGB channels
static void equalize_rgb(unsigned char *pixels, int w, int h, int ch)
{
    if (ch < 3)
        return; // Only process if image has at least 3 channels
    size_t npix = (size_t)w * h;
    int hist[3][256] = {{0}}, cdf[3][256];
    for (size_t i = 0; i < npix; i++)
    {
        int b = i * ch;
        // Build histogram for each channel
        hist[0][pixels[b]]++;
        hist[1][pixels[b + 1]]++;
        hist[2][pixels[b + 2]]++;
    }
    for (int c = 0; c < 3; c++)
    {
        int acc = 0;
        // Compute cumulative distribution function (CDF)
        for (int v = 0; v < 256; v++)
        {
            acc += hist[c][v];
            cdf[c][v] = acc;
        }
    }
    for (size_t i = 0; i < npix; i++)
    {
        int b = i * ch;
        // Apply equalization to each pixel
        for (int c = 0; c < 3; c++)
        {
            int old = pixels[b + c];
            int newv = (cdf[c][old] * 255) / (int)npix;
            if (newv < 0)
                newv = 0;
            if (newv > 255)
                newv = 255;
            pixels[b + c] = (unsigned char)newv;
        }
    }
}

// Classify image by dominant color channel
static const char *classify(unsigned char *p, int w, int h, int ch)
{
    unsigned long long R = 0, G = 0, B = 0;
    size_t npix = (size_t)w * h;
    for (size_t i = 0; i < npix; i++)
    {
        int b = i * ch;
        // Sum up values for each channel
        R += p[b];
        G += p[b + 1];
        B += p[b + 2];
    }
    // Return the color with the highest sum
    if (R >= G && R >= B)
        return "rojas";
    if (G >= R && G >= B)
        return "verdes";
    return "azules";
}

// Process an image file: equalize, classify, and save
static void process_image(const char *inpath, const char *client)
{
    int w, h, ch;
    unsigned char *img = stbi_load(inpath, &w, &h, &ch, 0); // Load image from disk
    if (!img)
    {
        // Log if image loading fails
        logmsg(client, inpath, "LOAD_FAIL");
        return;
    }
    equalize_rgb(img, w, h, ch);               // Apply histogram equalization
    const char *cls = classify(img, w, h, ch); // Classify image

    char out_proc[PATH_MAX * 2];
    // Keep original filename for output
    const char *basename = strrchr(inpath, '/');
    if (basename)
        basename++;
    else
        basename = inpath;
    char name_only[MAX_FILENAME_LEN + 1];
    strncpy(name_only, basename, sizeof(name_only) - 1);
    name_only[sizeof(name_only) - 1] = '\0';

    // Build processed image path
    snprintf(out_proc, sizeof(out_proc), "%s/processed/%s", base_dir, name_only);
    ensure_dir_for_file(out_proc);

    // Save processed image as PNG
    if (stbi_write_png(out_proc, w, h, ch, img, w * ch) == 0)
    {
        logmsg(client, out_proc, "SAVE_PROC_FAIL");
    }

    // Build classification path
    char out_cls[PATH_MAX * 2];
    snprintf(out_cls, sizeof(out_cls), "%s/classify/%s/%s", base_dir, cls, name_only);
    ensure_dir_for_file(out_cls);

    // Save classified image as PNG
    if (stbi_write_png(out_cls, w, h, ch, img, w * ch) == 0)
    {
        logmsg(client, out_cls, "SAVE_CLASS_FAIL");
    }

    stbi_image_free(img);        // Free image memory
    logmsg(client, inpath, cls); // Log classification
}

// Receive exactly 'len' bytes from a socket
static ssize_t recv_all(int fd, void *buf, size_t len)
{
    size_t got = 0;
    char *p = buf;
    while (got < len)
    {
        ssize_t r = recv(fd, p + got, len - got, 0);
        if (r <= 0)
            return r; // Return error or disconnect
        got += (size_t)r;
    }
    return (ssize_t)got;
}

// Thread function to handle a client connection
static void *client_thread(void *arg)
{
    int cfd = *(int *)arg;
    free(arg);
    struct sockaddr_in addr;
    socklen_t alen = sizeof(addr);
    // Get client IP address
    if (getpeername(cfd, (struct sockaddr *)&addr, &alen) != 0)
    {
        addr.sin_addr.s_addr = 0;
    }
    char ip[INET_ADDRSTRLEN] = "-";
    if (addr.sin_addr.s_addr != 0)
        inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));

    // Receive header (20 bytes)
    unsigned char header[20];
    if (recv_all(cfd, header, 20) != 20)
    {
        close(cfd);
        return NULL;
    }
    // header[0..3]: MAGIC
    // header[4]: PROTO_VERSION
    // header[5]: flags
    uint16_t nlen_n;
    memcpy(&nlen_n, header + 6, 2);
    uint16_t nlen = ntohs(nlen_n); // Filename length
    char nlen_msg[64];
    snprintf(nlen_msg, sizeof(nlen_msg), "DEBUG_NLEN_%u", nlen);
    logmsg(ip, "-", nlen_msg);
    if (nlen == 0 || nlen > MAX_FILENAME_LEN)
    {
        // Invalid filename length
        logmsg(ip, "-", "BAD_NAME_LEN");
        close(cfd);
        return NULL;
    }
    uint64_t sz_n;
    memcpy(&sz_n, header + 8, 8);
    uint64_t fsize = be64toh(sz_n); // File size
    uint32_t crc_n;
    memcpy(&crc_n, header + 16, 4);
    uint32_t crc32 = be32toh(crc_n); // CRC32 (unused)

    char fname[MAX_FILENAME_LEN + 1];
    memset(fname, 0, sizeof(fname));
    // Receive filename
    if (recv_all(cfd, fname, nlen) != (ssize_t)nlen)
    {
        logmsg(ip, "-", "RECV_NAME_FAIL");
        close(cfd);
        return NULL;
    }
    fname[nlen] = '\0';

    // Sanitize filename: keep only basename (prevent directory traversal)
    char *safe_name = fname;
    char *bs = strrchr(fname, '/');
    if (bs)
        safe_name = bs + 1;
    if (strlen(safe_name) == 0)
    {
        logmsg(ip, fname, "EMPTY_NAME_AFTER_SANITIZE");
        close(cfd);
        return NULL;
    }
    if (fsize == 0 || fsize > MAX_FILESIZE_BYTES)
    {
        // Invalid file size
        logmsg(ip, safe_name, "BAD_FILESIZE");
        close(cfd);
        return NULL;
    }

    // Build output path and ensure directories exist
    char outpath[PATH_MAX * 2];
    if (base_dir[strlen(base_dir) - 1] == '/')
    {
        snprintf(outpath, sizeof(outpath), "%s%s", base_dir, safe_name);
    }
    else
    {
        snprintf(outpath, sizeof(outpath), "%s/%s", base_dir, safe_name);
    }
    ensure_dir_for_file(outpath);

    FILE *f = fopen(outpath, "wb"); // Open file for writing
    if (!f)
    {
        perror("fopen");
        logmsg(ip, safe_name, "OPEN_FAIL");
        close(cfd);
        return NULL;
    }

    char buf[8192];
    uint64_t remain = fsize;
    // Receive file data in chunks
    while (remain > 0)
    {
        size_t chunk = remain > sizeof(buf) ? sizeof(buf) : (size_t)remain;
        ssize_t r = recv(cfd, buf, chunk, 0);
        if (r <= 0)
        {
            logmsg(ip, safe_name, "RECV_DATA_FAIL");
            fclose(f);
            unlink(outpath); // Remove incomplete file
            close(cfd);
            return NULL;
        }
        fwrite(buf, 1, (size_t)r, f);
        remain -= (size_t)r;
    }
    fclose(f);

    // Process the image (safe: process_image validates load)
    process_image(outpath, ip);

    // Send OK response to client
    const char *ok = "OK\n";
    send(cfd, ok, strlen(ok), 0);
    close(cfd);
    return NULL;
}

// Main server entry point
int main()
{
    load_config(CONFIG_FILE); // Load configuration
    ensure_dirs();            // Ensure required directories exist

    // Create listening socket
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0)
    {
        perror("socket");
        return 1;
    }
    int yes = 1;
    if (setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) != 0)
    {
        perror("setsockopt");
        // Continue anyway
    }
    struct sockaddr_in serv = {0};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(server_port);
    serv.sin_addr.s_addr = INADDR_ANY;
    if (bind(lfd, (struct sockaddr *)&serv, sizeof(serv)) != 0)
    {
        perror("bind");
        close(lfd);
        return 1;
    }
    if (listen(lfd, BACKLOG) != 0)
    {
        perror("listen");
        close(lfd);
        return 1;
    }

    printf("Server ImageServer listening on port %d\n", server_port);

    // Accept clients in a loop
    while (1)
    {
        struct sockaddr_in cli;
        socklen_t clilen = sizeof(cli);
        int *cfd = malloc(sizeof(int));
        if (!cfd)
        {
            perror("malloc");
            continue;
        }
        *cfd = accept(lfd, (struct sockaddr *)&cli, &clilen);
        if (*cfd < 0)
        {
            free(cfd);
            perror("accept");
            continue;
        }
        pthread_t th;
        if (pthread_create(&th, NULL, client_thread, cfd) != 0)
        {
            perror("pthread_create");
            close(*cfd);
            free(cfd);
            continue;
        }
        pthread_detach(th);
    }

    close(lfd);
    return 0;
}
