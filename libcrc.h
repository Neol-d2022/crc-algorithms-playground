#ifndef _LIBCRC_H_INCLUDED_
#define _LIBCRC_H_INCLUDED_

typedef unsigned char      _libcrc_uint8_t ;
typedef unsigned short     _libcrc_uint16_t;
typedef unsigned int       _libcrc_uint32_t;
typedef unsigned long long _libcrc_uint64_t;

#define LIBCRC_ALGORITHM_ENTRY_FLAG_REFIN  0x01
#define LIBCRC_ALGORITHM_ENTRY_FLAG_REFOUT 0x02
#define LIBCRC_ALGORITHM_ENTRY_FLAG_REFALL 0x04

struct libcrc_algorithm_entry_struct_t;
typedef _libcrc_uint64_t (*libcrc_compute_crc_t)(_libcrc_uint64_t crc, const struct libcrc_algorithm_entry_struct_t *algo, const void *data, unsigned int length);

typedef struct libcrc_algorithm_entry_struct_t {
    _libcrc_uint64_t table[256];
    _libcrc_uint64_t poly;
    _libcrc_uint64_t init;
    _libcrc_uint64_t xorout;
    _libcrc_uint64_t check;
    _libcrc_uint8_t  width;
    _libcrc_uint8_t  flags;
    const char *name;
    libcrc_compute_crc_t libcrc_compute_crc;
} libcrc_algorithm_entry_t;

int libcrc_init(void);
const libcrc_algorithm_entry_t *libcrc_get_algorithm_by_name(const char *algo_name);

_libcrc_uint64_t libcrc_compute_crc_init(const struct libcrc_algorithm_entry_struct_t *algo);
libcrc_compute_crc_t libcrc_compute_crc_func(const struct libcrc_algorithm_entry_struct_t *algo);
_libcrc_uint64_t libcrc_compute_crc_finish(_libcrc_uint64_t crc, const struct libcrc_algorithm_entry_struct_t *algo);

#endif
