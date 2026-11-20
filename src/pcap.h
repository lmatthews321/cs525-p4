#ifndef PCAP_H
#define PCAP_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    /* Status values returned while initializing or advancing the reader. */
    PCAP_OK = 0,
    PCAP_END = 1,
    PCAP_TRUNCATED = 2,
    PCAP_INVALID = 3
} PcapStatus;

typedef struct {
    /* Owns no buffer; data and length describe the capture supplied by the caller. */
    const uint8_t *data;
    size_t length;
    size_t position;
    int little_endian;
    uint32_t snaplen;
    uint32_t linktype;
    int valid;
} PcapReader;

typedef struct {
    /* One pcap record header and a bounded view of the following frame bytes. */
    uint32_t seconds;
    uint32_t microseconds;
    uint32_t captured_length;
    uint32_t original_length;
    const uint8_t *data;
} PcapRecord;

/* Validate and initialize a reader over caller-owned bytes. */
PcapStatus pcap_reader_init(PcapReader *reader, const uint8_t *data, size_t length);

/* Advance to the next record and expose a bounded pointer to its frame. */
PcapStatus pcap_reader_next(PcapReader *reader, PcapRecord *record);

#endif
