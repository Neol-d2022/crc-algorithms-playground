#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>

#include <sys/stat.h>

#include "libcrc.h"

static double time_diff(const struct timespec *from, const struct timespec *to)
{
    double diff;

    diff  = to->tv_nsec - from->tv_nsec;
    diff *= 0.000000001;
    diff += to->tv_sec - from->tv_sec;

    return diff;
}

int main(int argc, char **argv)
{
    unsigned char *buffer;
    struct timespec t[2];
    double time_io, time_crc;
    unsigned int length, total, buffer_length;
    int fd;
    
    _libcrc_uint64_t crc;
    const libcrc_algorithm_entry_t *algo;
    libcrc_compute_crc_t libcrc_compute_crc;

    //const char *algo_names[] = {"CRC-8/AUTOSAR", "CRC-10/ATM", "CRC-16/GSM", "CRC-32/ISO-HDLC", "CRC-64/XZ", NULL};
    const char *algo_names[] = {"CRC-32/ISO-HDLC", "CRC-64/XZ", NULL};
    unsigned int i;

    if (argc <= 1)
        return 1;

    buffer = (unsigned char*)malloc(buffer_length = 16777216);
    if(!buffer)
        return 1;

    if (libcrc_init())
    {
        fprintf(stderr, "libcrc_init() failed.\n");
        return 1;
    }

    fd = open(argv[1], O_RDONLY);
    if (fd < 0)
        return 1;

    while(algo_names[i])
    {
        algo = libcrc_get_algorithm_by_name(algo_names[i]);
        if (!algo)
        {
            printf("No Algorithm: %s.\n", algo_names[i]);
            return 1;
        }
        
        total = 0;
        lseek(fd, 0, SEEK_SET);
        crc                = libcrc_compute_crc_init(algo);
        libcrc_compute_crc = libcrc_compute_crc_func(algo);
        time_io = time_crc = 0.0;
    
        clock_gettime(CLOCK_MONOTONIC, t + 0);
        while ((length = read(fd, buffer, buffer_length)) > 0)
        {
            clock_gettime(CLOCK_MONOTONIC, t + 1);
            time_io += time_diff(t + 0, t + 1);

            clock_gettime(CLOCK_MONOTONIC, t + 0);
            crc  = libcrc_compute_crc(crc, algo, buffer, length);
            clock_gettime(CLOCK_MONOTONIC, t + 1);
            time_crc += time_diff(t + 0, t + 1);

            total += length;
            printf((length == buffer_length) ? "-" : ".");
        }
        crc = libcrc_compute_crc_finish(crc, algo);

        printf("\n");
        printf("Name   = %18s\n"      , algo_names[i]);
        printf("Length = %18u\n"      , total);
        printf("CRC    = 0x%016llX\n" , (unsigned long long)crc);
        printf("T I/O  = %18.8lf\n"   , time_io);
        printf("T CRC  = %18.8lf\n"   , time_crc);
        printf("\n");

        i++;
    }

    close(fd);
    free(buffer);

    return 0;
}
