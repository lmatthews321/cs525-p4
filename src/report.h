#ifndef REPORT_H
#define REPORT_H

#include "pcap.h"
#include "headers.h"

#include <stdio.h>

typedef struct {
    /* One formatted frame line produced for capture output. */
    char text[512];
} FrameReport;

typedef struct {
    /* Aggregate packet and byte statistics for one bidirectional flow. */
    char protocol[8];
    char endpoint_a[64];
    char endpoint_b[64];
    uint32_t packets;
    uint64_t bytes;
    uint32_t address_a;
    uint32_t address_b;
    uint16_t port_a;
    uint16_t port_b;
} FlowEntry;

typedef struct {
    /* Dynamically sized collection of observed flows. */
    FlowEntry *entries;
    size_t count;
    size_t capacity;
} FlowTable;

/* Decode one frame and optionally update its bidirectional flow entry. */
ParseStatus decode_frame(const uint8_t *frame, size_t length,
                         uint32_t seconds, uint32_t microseconds,
                         uint32_t frame_number, FlowTable *flows,
                         FrameReport *report);

/* Initialize/free the dynamic flow table or report a full capture to FILE. */
void flow_table_init(FlowTable *flows);
void flow_table_free(FlowTable *flows);
int report_capture(const PcapReader *reader, FILE *output);
int report_capture_bytes(const uint8_t *data, size_t length, FILE *output);
int report_capture_bytes_summary(const uint8_t *data, size_t length, FILE *output);

#endif
