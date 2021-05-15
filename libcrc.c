#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "libcrc.h"

#define LIBCRC_ALGORITHM_ENTRY_CHECK_STRING "123456789"

/* https://reveng.sourceforge.io/crc-catalogue/all.htm */
static libcrc_algorithm_entry_t g_libcrc_algorithms[] = {
    {   /* CRC-8/AUTOSAR */
        {0},
        (_libcrc_uint64_t) 0x000000000000002Fllu, /* poly */
        (_libcrc_uint64_t) 0x00000000000000FFllu, /* init */
        (_libcrc_uint64_t) 0x00000000000000FFllu, /* xorout */
        (_libcrc_uint64_t) 0x00000000000000DFllu, /* check */
        (_libcrc_uint8_t)  8,                     /* width */
        (_libcrc_uint8_t)  0,                     /* flags */
        "CRC-8/AUTOSAR",
        NULL,
    },
    {   /* CRC-10/ATM */
        {0},
        (_libcrc_uint64_t) 0x0000000000000233llu, /* poly */
        (_libcrc_uint64_t) 0x0000000000000000llu, /* init */
        (_libcrc_uint64_t) 0x0000000000000000llu, /* xorout */
        (_libcrc_uint64_t) 0x0000000000000199llu, /* check */
        (_libcrc_uint8_t)  10,                    /* width */
        (_libcrc_uint8_t)  0,                     /* flags */
        "CRC-10/ATM",
        NULL
    },
    {   /* CRC-16/GSM */
        {0},
        (_libcrc_uint64_t) 0x0000000000001021llu, /* poly */
        (_libcrc_uint64_t) 0x0000000000000000llu, /* init */
        (_libcrc_uint64_t) 0x000000000000FFFFllu, /* xorout */
        (_libcrc_uint64_t) 0x000000000000CE3Cllu, /* check */
        (_libcrc_uint8_t)  16,                    /* width */
        (_libcrc_uint8_t)  0,                     /* flags */
        "CRC-16/GSM",
        NULL
    },
    {   /* CRC-32/ISO-HDLC */
        {0},
        (_libcrc_uint64_t) 0x0000000004C11DB7llu, /* poly */
        (_libcrc_uint64_t) 0x00000000FFFFFFFFllu, /* init */
        (_libcrc_uint64_t) 0x00000000FFFFFFFFllu, /* xorout */
        (_libcrc_uint64_t) 0x00000000CBF43926llu, /* check */
        (_libcrc_uint8_t)  32,                    /* width */
        (_libcrc_uint8_t)  (LIBCRC_ALGORITHM_ENTRY_FLAG_REFIN | LIBCRC_ALGORITHM_ENTRY_FLAG_REFOUT), /* flags */
        "CRC-32/ISO-HDLC",
        NULL
    },
    {   /* CRC-64/XZ */
        {0},
        (_libcrc_uint64_t) 0x42F0E1EBA9EA3693llu, /* poly */
        (_libcrc_uint64_t) 0xFFFFFFFFFFFFFFFFllu, /* init */
        (_libcrc_uint64_t) 0xFFFFFFFFFFFFFFFFllu, /* xorout */
        (_libcrc_uint64_t) 0x995DC9BBDF1939FAllu, /* check */
        (_libcrc_uint8_t)  64,                    /* width */
        (_libcrc_uint8_t)  (LIBCRC_ALGORITHM_ENTRY_FLAG_REFIN | LIBCRC_ALGORITHM_ENTRY_FLAG_REFOUT), /* flags */
        "CRC-64/XZ",
        NULL
    },
};

static _libcrc_uint64_t libcrc_reflect_value(_libcrc_uint64_t value, _libcrc_uint8_t width)
{
    _libcrc_uint64_t retval;
    _libcrc_uint8_t i;

    retval ^= retval;
    for (i = 0; i < width; i++)
        if (value & (1llu << i))
            retval |= (1llu << (width - 1llu - i));

    //fprintf(stderr, "[libcrc][libcrc_reflect_value] 0x%016llX -> 0x%016llX.\n"
    //    , (unsigned long long)value, (unsigned long long)retval);
    return retval;
}

typedef _libcrc_uint64_t (*libcrc_compute_crc_for_byte_t)(const libcrc_algorithm_entry_t *, _libcrc_uint64_t);
static _libcrc_uint64_t libcrc_compute_crc_for_byte_f(const libcrc_algorithm_entry_t *algo, _libcrc_uint64_t byte)
{
    _libcrc_uint64_t i;
    _libcrc_uint64_t topbit;
    _libcrc_uint64_t mask;
    _libcrc_uint64_t poly  = algo->poly;
    _libcrc_uint8_t  width = algo->width;

    byte = (byte & 0xFF) << (width - 8);
    topbit = 1llu << (width - 1);
    mask = (1llu << width) - 1;

    for (i = 0; i < 8; i++)
        if (byte & topbit)
            byte = ((byte << 1) ^ poly);
        else
            byte =  (byte << 1);
    
    return byte & mask;
}

static _libcrc_uint64_t libcrc_compute_crc_for_byte_r(const libcrc_algorithm_entry_t *algo, _libcrc_uint64_t byte)
{
    _libcrc_uint64_t i;
    _libcrc_uint64_t poly  = algo->poly;

    for (i = 0; i < 8; i++)
        if (byte & 1llu)
            byte = ((byte >> 1) ^ poly);
        else
            byte =  (byte >> 1);
    
    return byte;
}

static _libcrc_uint64_t libcrc_compute_crc_f(_libcrc_uint64_t crc, const libcrc_algorithm_entry_t *algo, const void *data, unsigned int length)
{
    const _libcrc_uint64_t *table = algo->table;
    _libcrc_uint64_t  mask;
    _libcrc_uint64_t _data;
    unsigned int i;
    _libcrc_uint8_t  width = algo->width;

    mask = (1llu << width) - 1;
    for (i = 0; i < length; i++)
    {
        _data = ((unsigned char *)data)[i];
        //if (algo->flags & LIBCRC_ALGORITHM_ENTRY_FLAG_REFIN)
        //    _data = libcrc_reflect_value(_data, 8);
        _data ^= crc >> (width - 8);
        crc = (crc << 8) ^ table[_data & 0xFF];
    }

    return crc & mask;
}

static _libcrc_uint64_t libcrc_compute_crc_r(_libcrc_uint64_t crc, const libcrc_algorithm_entry_t *algo, const void *data, unsigned int length)
{
    const _libcrc_uint64_t *table = algo->table;
    _libcrc_uint64_t _data;
    unsigned int i;

    for (i = 0; i < length; i++)
    {
        _data = ((unsigned char *)data)[i];
        //if (algo->flags & LIBCRC_ALGORITHM_ENTRY_FLAG_REFIN)
        //    _data = libcrc_reflect_value(_data, 8);
        _data ^= crc & 0xFF;
        crc = (crc >> 8) ^ table[_data];
    }

    return crc;
}

static int libcrc_init_algorithm_entry(libcrc_algorithm_entry_t *entry)
{
    _libcrc_uint64_t byte;
    _libcrc_uint64_t crc;
    libcrc_compute_crc_for_byte_t libcrc_compute_crc_for_byte;
    libcrc_compute_crc_t libcrc_compute_crc;

    //fprintf(stderr, "[libcrc][libcrc_init_algorithm_entry] %s.\n", entry->name);

    if (entry->flags & (LIBCRC_ALGORITHM_ENTRY_FLAG_REFIN))
    {
        //fprintf(stderr, "[libcrc][libcrc_init_algorithm_entry] refin.\n");
        entry->poly   = libcrc_reflect_value(entry->poly, entry->width);
        entry->flags ^= LIBCRC_ALGORITHM_ENTRY_FLAG_REFIN | LIBCRC_ALGORITHM_ENTRY_FLAG_REFOUT;
        entry->flags |= LIBCRC_ALGORITHM_ENTRY_FLAG_REFALL;
    }

    if (entry->flags & LIBCRC_ALGORITHM_ENTRY_FLAG_REFALL)
    {
        //fprintf(stderr, "[libcrc][libcrc_init_algorithm_entry] %s, R.\n", entry->name);
        libcrc_compute_crc_for_byte = libcrc_compute_crc_for_byte_r;
        entry->libcrc_compute_crc = libcrc_compute_crc = libcrc_compute_crc_r;
    }
    else
    {
        //fprintf(stderr, "[libcrc][libcrc_init_algorithm_entry] %s, L.\n", entry->name);
        libcrc_compute_crc_for_byte = libcrc_compute_crc_for_byte_f;
        entry->libcrc_compute_crc = libcrc_compute_crc = libcrc_compute_crc_f;
    }

    for (byte = 0; byte < sizeof(entry->table) / sizeof(entry->table[0]); byte++)
        entry->table[byte] = libcrc_compute_crc_for_byte(entry, byte);
    
    //fprintf(stderr, "[libcrc][libcrc_init_algorithm_entry] %s, 0x%016llX.\n"
    //    , entry->name, (unsigned long long)entry->table[1]);

    crc  = entry->init;
    crc  = libcrc_compute_crc(crc, entry, LIBCRC_ALGORITHM_ENTRY_CHECK_STRING, strlen(LIBCRC_ALGORITHM_ENTRY_CHECK_STRING));
    if (entry->flags & LIBCRC_ALGORITHM_ENTRY_FLAG_REFOUT)
    {
        //fprintf(stderr, "[libcrc][libcrc_init_algorithm_entry] refout.\n");
        crc = libcrc_reflect_value(crc, entry->width);
    }
    crc ^= entry->xorout;
    
    //fprintf(stderr, "[libcrc][libcrc_init_algorithm_entry] %s, 0x%016llX, 0x%016llX.\n"
    //    , entry->name, (unsigned long long)crc, (unsigned long long)entry->check);
    if (crc != entry->check)
    {
        fprintf(stderr, "Initialization failed for '%s'.\n", entry->name);
        fprintf(stderr, "Please check your configurations.\n");
        return 1;
    }

    return 0;
}

static int libcrc_compare_entry(const void *a, const void *b)
{
    const libcrc_algorithm_entry_t *c = (const libcrc_algorithm_entry_t *)a;
    const libcrc_algorithm_entry_t *d = (const libcrc_algorithm_entry_t *)b;

    return strcmp(c->name, d->name);
}

int libcrc_init(void)
{
    unsigned int i, n = sizeof(g_libcrc_algorithms) / sizeof(g_libcrc_algorithms[0]);

    for (i = 0; i < n; i++)
    {
        if (libcrc_init_algorithm_entry(g_libcrc_algorithms + i))
            return 1;
    }

    qsort(g_libcrc_algorithms, n, sizeof(g_libcrc_algorithms[0]), libcrc_compare_entry);

    return 0;
}

const libcrc_algorithm_entry_t *libcrc_get_algorithm_by_name(const char *algo_name)
{
    libcrc_algorithm_entry_t key;

    key.name = algo_name;
    return (const libcrc_algorithm_entry_t *)bsearch(&key, g_libcrc_algorithms, sizeof(g_libcrc_algorithms) / sizeof(g_libcrc_algorithms[0]), sizeof(g_libcrc_algorithms[0]), libcrc_compare_entry);
}

_libcrc_uint64_t libcrc_compute_crc_init(const struct libcrc_algorithm_entry_struct_t *algo)
{
    return algo->init;
}

libcrc_compute_crc_t libcrc_compute_crc_func(const struct libcrc_algorithm_entry_struct_t *algo)
{
    return algo->libcrc_compute_crc;
}

_libcrc_uint64_t libcrc_compute_crc_finish(_libcrc_uint64_t crc, const struct libcrc_algorithm_entry_struct_t *algo)
{
    if (algo->flags & LIBCRC_ALGORITHM_ENTRY_FLAG_REFOUT)
    {
        //fprintf(stderr, "[libcrc][libcrc_init_algorithm_entry] refout.\n");
        crc = libcrc_reflect_value(crc, algo->width);
    }
    crc ^= algo->xorout;

    return crc;
}