#include "pcap.h"
#include "headers.h"
#include "report.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Read a 16-bit value in network/big-endian byte order. */
static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

/* Read a 32-bit value in network/big-endian byte order. */
static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* Read a 16-bit pcap header value in little-endian byte order. */
static uint16_t read_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/* Read a 32-bit pcap header value in little-endian byte order. */
static uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Select the pcap-header byte order for a 16-bit field. */
static uint16_t read_pcap16(const uint8_t *p, int little)
{
    return little ? read_le16(p) : read_be16(p);
}

/* Select the pcap-header byte order for a 32-bit field. */
static uint32_t read_pcap32(const uint8_t *p, int little)
{
    return little ? read_le32(p) : read_be32(p);
}

/* Initialize an in-memory pcap reader and validate its global header. */
PcapStatus pcap_reader_init(PcapReader *reader, const uint8_t *data, size_t length)
{
    if (reader == NULL) return PCAP_INVALID;
    memset(reader, 0, sizeof(*reader));
    if (data == NULL) return PCAP_INVALID;
    if (length < 24) return PCAP_TRUNCATED;

    /* Interpret the same magic bytes twice to infer the pcap file byte order. */
    uint32_t little_magic = read_le32(data);
    uint32_t big_magic = read_be32(data);
    if (little_magic == 0xa1b2c3d4u) {
        reader->little_endian = 1;
    } else if (big_magic == 0xa1b2c3d4u) {
        reader->little_endian = 0;
    } else {
        return PCAP_INVALID;
    }

    uint16_t major = read_pcap16(data + 4, reader->little_endian);
    uint16_t minor = read_pcap16(data + 6, reader->little_endian);
    uint32_t linktype = read_pcap32(data + 20, reader->little_endian);
    if (major != 2 || minor != 4 || linktype != 1) return PCAP_INVALID;

    reader->data = data;
    reader->length = length;
    reader->position = 24;
    reader->snaplen = read_pcap32(data + 16, reader->little_endian);
    reader->linktype = linktype;
    reader->valid = 1;
    return PCAP_OK;
}

/* Return the next bounded record, or a status for end/truncation/error. */
PcapStatus pcap_reader_next(PcapReader *reader, PcapRecord *record)
{
    if (reader == NULL || record == NULL || !reader->valid) return PCAP_INVALID;
    if (reader->position == reader->length) return PCAP_END;
    if (reader->length - reader->position < 16) return PCAP_TRUNCATED;

    const uint8_t *header = reader->data + reader->position;
    /* Never advance or expose frame bytes unless the complete captured body fits. */
    uint32_t captured = read_pcap32(header + 8, reader->little_endian);
    size_t remaining = reader->length - reader->position - 16;
    if ((size_t)captured > remaining) return PCAP_TRUNCATED;

    record->seconds = read_pcap32(header, reader->little_endian);
    record->microseconds = read_pcap32(header + 4, reader->little_endian);
    record->captured_length = captured;
    record->original_length = read_pcap32(header + 12, reader->little_endian);
    record->data = header + 16;
    reader->position += 16 + (size_t)captured;
    return PCAP_OK;
}

/* Parse the fixed 14-byte Ethernet II header without crossing the frame length. */
ParseStatus parse_ethernet(const uint8_t *data, size_t length, EthernetHeader *out)
{
    if (out == NULL) return PARSE_INVALID;
    if (data == NULL) return PARSE_INVALID;
    if (length < 14) return PARSE_TRUNCATED;
    memcpy(out->destination, data, 6);
    memcpy(out->source, data + 6, 6);
    out->ether_type = read_be16(data + 12);
    return PARSE_OK;
}

/* Parse and validate a fixed Ethernet/IPv4 ARP header. */
ParseStatus parse_arp(const uint8_t *data, size_t length, ArpHeader *out)
{
    if (out == NULL) return PARSE_INVALID;
    if (data == NULL) return PARSE_INVALID;
    if (length < 28) return PARSE_TRUNCATED;
    memset(out, 0, sizeof(*out));
    out->hardware_type = read_be16(data);
    out->protocol_type = read_be16(data + 2);
    out->hardware_length = data[4];
    out->protocol_length = data[5];
    out->operation = read_be16(data + 6);
    if (out->hardware_type != 1 || out->protocol_type != 0x0800 ||
        out->hardware_length != 6 || out->protocol_length != 4) {
        return PARSE_INVALID;
    }
    memcpy(out->sender_hardware, data + 8, 6);
    memcpy(out->sender_protocol, data + 14, 4);
    memcpy(out->target_hardware, data + 18, 6);
    memcpy(out->target_protocol, data + 24, 4);
    return PARSE_OK;
}

/* Parse an IPv4 header and provide only the payload bytes actually available. */
ParseStatus parse_ipv4(const uint8_t *data, size_t length, Ipv4Header *out)
{
    if (out == NULL) return PARSE_INVALID;
    if (data == NULL) return PARSE_INVALID;
    if (length < 20) return PARSE_TRUNCATED;
    memset(out, 0, sizeof(*out));
    out->version = (uint8_t)(data[0] >> 4);
    out->ihl = (uint8_t)(data[0] & 0x0fu);
    out->header_length = (uint8_t)(out->ihl * 4u);
    if (out->version != 4 || out->header_length < 20 ||
        (size_t)out->header_length > length) return PARSE_INVALID;

    uint16_t total = read_be16(data + 2);
    if (total < out->header_length) return PARSE_INVALID;
    out->dscp = (uint8_t)(data[1] >> 2);
    out->ecn = (uint8_t)(data[1] & 3u);
    out->total_length = total;
    out->identification = read_be16(data + 4);
    uint16_t fragment = read_be16(data + 6);
    out->flags = (uint8_t)((fragment >> 13) & 7u);
    out->fragment_offset = (uint16_t)(fragment & 0x1fffu);
    out->ttl = data[8];
    out->protocol = data[9];
    out->checksum = read_be16(data + 10);
    out->source = read_be32(data + 12);
    out->destination = read_be32(data + 16);
    /* Snaplen/truncation may leave less than total_length; expose only what exists. */
    out->payload = data + out->header_length;
    size_t payload_available = length - out->header_length;
    size_t payload_declared = (size_t)total - out->header_length;
    out->payload_length = payload_declared < payload_available ?
                          payload_declared : payload_available;
    return PARSE_OK;
}

/* Parse a TCP header and validate its variable header length. */
ParseStatus parse_tcp(const uint8_t *data, size_t length, TcpHeader *out)
{
    if (out == NULL) return PARSE_INVALID;
    if (data == NULL) return PARSE_INVALID;
    if (length < 20) return PARSE_TRUNCATED;
    memset(out, 0, sizeof(*out));
    out->source_port = read_be16(data);
    out->destination_port = read_be16(data + 2);
    out->sequence = read_be32(data + 4);
    out->acknowledgement = read_be32(data + 8);
    out->header_length = (uint8_t)((data[12] >> 4) * 4u);
    if (out->header_length < 20 || (size_t)out->header_length > length) {
        return PARSE_INVALID;
    }
    out->flags = data[13];
    out->window = read_be16(data + 14);
    out->checksum = read_be16(data + 16);
    out->urgent_pointer = read_be16(data + 18);
    return PARSE_OK;
}

/* Parse and validate the fixed eight-byte UDP header. */
ParseStatus parse_udp(const uint8_t *data, size_t length, UdpHeader *out)
{
    if (out == NULL) return PARSE_INVALID;
    if (data == NULL) return PARSE_INVALID;
    if (length < 8) return PARSE_TRUNCATED;
    memset(out, 0, sizeof(*out));
    out->source_port = read_be16(data);
    out->destination_port = read_be16(data + 2);
    out->length = read_be16(data + 4);
    out->checksum = read_be16(data + 6);
    if (out->length < 8) return PARSE_INVALID;
    return PARSE_OK;
}

/* Compute an Internet one's-complement checksum over bounded bytes. */
uint16_t internet_checksum(const uint8_t *data, size_t length)
{
    if (data == NULL) return 0;
    uint32_t sum = 0;
    while (length >= 2) {
        sum += ((uint32_t)data[0] << 8) | (uint32_t)data[1];
        data += 2;
        length -= 2;
    }
    if (length == 1) sum += (uint32_t)data[0] << 8;
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)(~sum & 0xffffu);
}

/* Format six Ethernet address bytes as lowercase colon-separated hex. */
void format_mac_address(const uint8_t address[6], char output[18])
{
    if (output == NULL) return;
    if (address == NULL) {
        output[0] = '\0';
        return;
    }
    (void)snprintf(output, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                   address[0], address[1], address[2],
                   address[3], address[4], address[5]);
}

/* Format a network-order IPv4 integer as dotted decimal. */
void format_ipv4_address(uint32_t address, char output[16])
{
    if (output == NULL) return;
    (void)snprintf(output, 16, "%u.%u.%u.%u",
                   (unsigned)((address >> 24) & 0xffu),
                   (unsigned)((address >> 16) & 0xffu),
                   (unsigned)((address >> 8) & 0xffu),
                   (unsigned)(address & 0xffu));
}

/* Format TCP flags in FIN/SYN/RST/PSH/URG/ECE/CWR order, then ACK. */
void format_tcp_flags(uint8_t flags, char output[32])
{
    if (output == NULL) return;
    if (flags == 0) {
        (void)snprintf(output, 32, "none");
        return;
    }
    size_t n = 0;
    static const uint8_t bits[] = {0x01u, 0x02u, 0x04u, 0x08u,
                                   0x20u, 0x40u, 0x80u};
    static const char names[] = {'F', 'S', 'R', 'P', 'U', 'E', 'W'};
    for (size_t i = 0; i < sizeof(bits); ++i) {
        if ((flags & bits[i]) != 0 && n < 31) output[n++] = names[i];
    }
    if ((flags & 0x10u) != 0 && n < 31) output[n++] = '.';
    output[n] = '\0';
}

/* Compatibility aliases keep the three parser naming conventions interchangeable. */
ParseStatus ethernet_parse(const uint8_t *d, size_t l, EthernetHeader *o) { return parse_ethernet(d, l, o); }
ParseStatus arp_parse(const uint8_t *d, size_t l, ArpHeader *o) { return parse_arp(d, l, o); }
ParseStatus ipv4_parse(const uint8_t *d, size_t l, Ipv4Header *o) { return parse_ipv4(d, l, o); }
ParseStatus tcp_parse(const uint8_t *d, size_t l, TcpHeader *o) { return parse_tcp(d, l, o); }
ParseStatus udp_parse(const uint8_t *d, size_t l, UdpHeader *o) { return parse_udp(d, l, o); }
ParseStatus parse_ethernet_header(const uint8_t *d, size_t l, EthernetHeader *o) { return parse_ethernet(d, l, o); }
ParseStatus parse_arp_header(const uint8_t *d, size_t l, ArpHeader *o) { return parse_arp(d, l, o); }
ParseStatus parse_ipv4_header(const uint8_t *d, size_t l, Ipv4Header *o) { return parse_ipv4(d, l, o); }
ParseStatus parse_tcp_header(const uint8_t *d, size_t l, TcpHeader *o) { return parse_tcp(d, l, o); }
ParseStatus parse_udp_header(const uint8_t *d, size_t l, UdpHeader *o) { return parse_udp(d, l, o); }
uint16_t checksum(const uint8_t *d, size_t l) { return internet_checksum(d, l); }
void mac_address_format(const uint8_t a[6], char o[18]) { format_mac_address(a, o); }
void ipv4_address_format(uint32_t a, char o[16]) { format_ipv4_address(a, o); }
void tcp_flags_format(uint8_t f, char o[32]) { format_tcp_flags(f, o); }

/* Initialize an empty dynamic flow table. */
void flow_table_init(FlowTable *flows)
{
    if (flows != NULL) {
        flows->entries = NULL;
        flows->count = 0;
        flows->capacity = 0;
    }
}

/* Release the dynamic flow entries and reset table state. */
void flow_table_free(FlowTable *flows)
{
    if (flows == NULL) return;
    free(flows->entries);
    flows->entries = NULL;
    flows->count = 0;
    flows->capacity = 0;
}

/* Validate TCP/UDP checksum by folding in the IPv4 pseudo-header. */
static int transport_checksum_valid(const Ipv4Header *ip, const uint8_t *segment,
                                    size_t length, uint16_t checksum)
{
    /* A zero transport checksum means "not supplied" rather than invalid. */
    if (checksum == 0) return 1;
    uint32_t sum = ((uint32_t)(ip->source >> 16) & 0xffffu) +
                   ((uint32_t)ip->source & 0xffffu) +
                   ((uint32_t)(ip->destination >> 16) & 0xffffu) +
                   ((uint32_t)ip->destination & 0xffffu) +
                   (uint32_t)ip->protocol + (uint32_t)length;
    for (size_t i = 0; i + 1 < length; i += 2) {
        sum += ((uint32_t)segment[i] << 8) | (uint32_t)segment[i + 1];
    }
    if ((length & 1u) != 0) sum += (uint32_t)segment[length - 1] << 8;
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)(~sum & 0xffffu) == 0;
}

/* Find a bidirectional flow or append a canonicalized flow entry. */
static FlowEntry *flow_find_or_add(FlowTable *flows, const char *protocol,
                                   uint32_t address_a, uint16_t port_a,
                                   uint32_t address_b, uint16_t port_b)
{
    if (flows == NULL) return NULL;
    /* Canonical ordering makes packets in both directions share one flow entry. */
    if (address_a > address_b ||
        (address_a == address_b && port_a > port_b)) {
        uint32_t ta = address_a;
        uint16_t tp = port_a;
        address_a = address_b;
        port_a = port_b;
        address_b = ta;
        port_b = tp;
    }
    for (size_t i = 0; i < flows->count; ++i) {
        FlowEntry *entry = &flows->entries[i];
        if (strcmp(entry->protocol, protocol) == 0 &&
            entry->address_a == address_a && entry->port_a == port_a &&
            entry->address_b == address_b && entry->port_b == port_b) {
            return entry;
        }
    }
    if (flows->count == flows->capacity) {
        size_t capacity = flows->capacity == 0 ? 8 : flows->capacity * 2;
        FlowEntry *entries = realloc(flows->entries, capacity * sizeof(*entries));
        if (entries == NULL) return NULL;
        flows->entries = entries;
        flows->capacity = capacity;
    }
    FlowEntry *entry = &flows->entries[flows->count++];
    memset(entry, 0, sizeof(*entry));
    (void)snprintf(entry->protocol, sizeof(entry->protocol), "%s", protocol);
    entry->address_a = address_a;
    entry->address_b = address_b;
    entry->port_a = port_a;
    entry->port_b = port_b;
    char address[16];
    format_ipv4_address(address_a, address);
    (void)snprintf(entry->endpoint_a, sizeof(entry->endpoint_a), "%s:%u",
                   address, (unsigned)port_a);
    format_ipv4_address(address_b, address);
    (void)snprintf(entry->endpoint_b, sizeof(entry->endpoint_b), "%s:%u",
                   address, (unsigned)port_b);
    return entry;
}

/* Walk one Ethernet frame down through ARP or IPv4/TCP/UDP and format it. */
ParseStatus decode_frame(const uint8_t *frame, size_t length,
                         uint32_t seconds, uint32_t microseconds,
                         uint32_t frame_number, FlowTable *flows,
                         FrameReport *report)
{
    if (report == NULL) return PARSE_INVALID;
    EthernetHeader ethernet;
    ParseStatus status = parse_ethernet(frame, length, &ethernet);
    if (status != PARSE_OK) {
        (void)snprintf(report->text, sizeof(report->text),
                       "%u %u.%06u malformed Ethernet",
                       (unsigned)frame_number, (unsigned)seconds,
                       (unsigned)microseconds);
        return status;
    }

    if (ethernet.ether_type == 0x0806u) {
        ArpHeader arp;
        status = parse_arp(frame + 14, length - 14, &arp);
        if (status != PARSE_OK) {
            (void)snprintf(report->text, sizeof(report->text),
                           "%u %u.%06u malformed ARP",
                           (unsigned)frame_number, (unsigned)seconds,
                           (unsigned)microseconds);
        } else if (arp.operation == 1u) {
            char sender[16], target[16];
            format_ipv4_address(read_be32(arp.sender_protocol), sender);
            format_ipv4_address(read_be32(arp.target_protocol), target);
            (void)snprintf(report->text, sizeof(report->text),
                           "%u %u.%06u ARP request who-has %s tell %s",
                           (unsigned)frame_number, (unsigned)seconds,
                           (unsigned)microseconds, target, sender);
        } else if (arp.operation == 2u) {
            char sender[16], sender_mac[18];
            format_ipv4_address(read_be32(arp.sender_protocol), sender);
            format_mac_address(arp.sender_hardware, sender_mac);
            (void)snprintf(report->text, sizeof(report->text),
                           "%u %u.%06u ARP reply %s is-at %s",
                           (unsigned)frame_number, (unsigned)seconds,
                           (unsigned)microseconds, sender, sender_mac);
        } else {
            (void)snprintf(report->text, sizeof(report->text),
                           "%u %u.%06u ARP op=%u",
                           (unsigned)frame_number, (unsigned)seconds,
                           (unsigned)microseconds, (unsigned)arp.operation);
        }
        return status;
    }

    if (ethernet.ether_type != 0x0800u) {
        (void)snprintf(report->text, sizeof(report->text),
                       "%u %u.%06u Ethernet type=0x%04x",
                       (unsigned)frame_number, (unsigned)seconds,
                       (unsigned)microseconds, (unsigned)ethernet.ether_type);
        return PARSE_OK;
    }

    Ipv4Header ip;
    status = parse_ipv4(frame + 14, length - 14, &ip);
    if (status != PARSE_OK) {
        (void)snprintf(report->text, sizeof(report->text),
                       "%u %u.%06u malformed IPv4",
                       (unsigned)frame_number, (unsigned)seconds,
                       (unsigned)microseconds);
        return status;
    }

    char source[16], destination[16];
    format_ipv4_address(ip.source, source);
    format_ipv4_address(ip.destination, destination);

    /* Fragmented datagrams are not fully decodable at the TCP/UDP layer. */
    if ((ip.flags & 1u) != 0 || ip.fragment_offset != 0) {
        (void)snprintf(report->text, sizeof(report->text),
                       "%u %u.%06u IPv4 %s > %s proto=%u fragment",
                       (unsigned)frame_number, (unsigned)seconds,
                       (unsigned)microseconds, source, destination,
                       (unsigned)ip.protocol);
        return PARSE_OK;
    }

    if (internet_checksum(frame + 14, ip.header_length) != 0) {
        (void)snprintf(report->text, sizeof(report->text),
                       "%u %u.%06u IPv4 %s > %s proto=%u bad-header-cksum",
                       (unsigned)frame_number, (unsigned)seconds,
                       (unsigned)microseconds, source, destination,
                       (unsigned)ip.protocol);
        return PARSE_OK;
    }

    if (ip.protocol == 17u) {
        UdpHeader udp;
        status = parse_udp(ip.payload, ip.payload_length, &udp);
        if (status != PARSE_OK) {
            (void)snprintf(report->text, sizeof(report->text),
                           "%u %u.%06u malformed UDP",
                           (unsigned)frame_number, (unsigned)seconds,
                           (unsigned)microseconds);
            return status;
        }
        /* A declared UDP length beyond captured IPv4 payload indicates malformed UDP. */
        if (ip.total_length <= (uint16_t)(length - 14u) &&
            udp.length > ip.payload_length) {
            (void)snprintf(report->text, sizeof(report->text),
                           "%u %u.%06u malformed UDP",
                           (unsigned)frame_number, (unsigned)seconds,
                           (unsigned)microseconds);
            return PARSE_INVALID;
        }
        int udp_payload = udp.length >= 8 ?
                          (int)udp.length - 8 : 0;
        const char *checksum_text;
        if (udp.checksum == 0) {
            checksum_text = "none";
        } else if (transport_checksum_valid(&ip, ip.payload,
                                            ip.payload_length, udp.checksum)) {
            checksum_text = "ok";
        } else {
            checksum_text = "bad";
        }
        (void)snprintf(report->text, sizeof(report->text),
                       "%u %u.%06u UDP %s:%u > %s:%u len=%d cksum=%s",
                       (unsigned)frame_number, (unsigned)seconds,
                       (unsigned)microseconds, source,
                       (unsigned)udp.source_port, destination,
                       (unsigned)udp.destination_port, udp_payload,
                       checksum_text);
        if (flows != NULL) {
            FlowEntry *flow = flow_find_or_add(
                flows, "UDP", ip.source, udp.source_port,
                ip.destination, udp.destination_port);
            if (flow != NULL) {
                flow->packets++;
                flow->bytes += (uint64_t)length;
            }
        }
        return PARSE_OK;
    }

    if (ip.protocol == 6u) {
        TcpHeader tcp;
        status = parse_tcp(ip.payload, ip.payload_length, &tcp);
        if (status != PARSE_OK) {
            (void)snprintf(report->text, sizeof(report->text),
                           "%u %u.%06u malformed TCP",
                           (unsigned)frame_number, (unsigned)seconds,
                           (unsigned)microseconds);
            return status;
        }
        char flags[32];
        format_tcp_flags(tcp.flags, flags);
        int tcp_payload = (int)ip.payload_length - (int)tcp.header_length;
        if (tcp_payload < 0) tcp_payload = 0;
        const char *checksum_text;
        if (tcp.checksum == 0) {
            checksum_text = "none";
        } else if (transport_checksum_valid(&ip, ip.payload,
                                            ip.payload_length, tcp.checksum)) {
            checksum_text = "ok";
        } else {
            checksum_text = "bad";
        }
        (void)snprintf(report->text, sizeof(report->text),
                       "%u %u.%06u TCP %s:%u > %s:%u [%s] seq=%u ack=%u win=%u len=%d cksum=%s",
                       (unsigned)frame_number, (unsigned)seconds,
                       (unsigned)microseconds, source,
                       (unsigned)tcp.source_port, destination,
                       (unsigned)tcp.destination_port, flags,
                       (unsigned)tcp.sequence, (unsigned)tcp.acknowledgement,
                       (unsigned)tcp.window, tcp_payload, checksum_text);
        if (flows != NULL) {
            FlowEntry *flow = flow_find_or_add(
                flows, "TCP", ip.source, tcp.source_port,
                ip.destination, tcp.destination_port);
            if (flow != NULL) {
                flow->packets++;
                flow->bytes += (uint64_t)length;
            }
        }
        return PARSE_OK;
    }

    (void)snprintf(report->text, sizeof(report->text),
                   "%u %u.%06u IPv4 %s > %s proto=%u",
                   (unsigned)frame_number, (unsigned)seconds,
                   (unsigned)microseconds, source, destination,
                   (unsigned)ip.protocol);
    return PARSE_OK;
}

/* Iterate an initialized in-memory reader and write frame and/or flow reports. */
static int report_capture_mode(const PcapReader *source, FILE *output,
                               int summary_only)
{
    if (source == NULL || output == NULL || !source->valid) return -1;
    PcapReader reader = *source;
    reader.position = 24;
    FlowTable flows;
    flow_table_init(&flows);

    PcapRecord record;
    uint32_t frame_number = 0;
    uint32_t first_seconds = 0;
    int have_first = 0;
    for (;;) {
        PcapStatus status = pcap_reader_next(&reader, &record);
        if (status == PCAP_END) break;
        if (status == PCAP_TRUNCATED) break;
        // Defensive fallback: a valid reader can only return OK, END, or TRUNCATED.
        // GCOVR_EXCL_START
        if (status != PCAP_OK) {
            flow_table_free(&flows);
            return -1;
        }
        // GCOVR_EXCL_STOP
        if (!have_first) {
            first_seconds = record.seconds;
            have_first = 1;
        }
        ++frame_number;
        FrameReport report;
        EthernetHeader ethernet;
        Ipv4Header ip;
        int malformed_length = 0;
        /* Detect declared IPv4 length extending beyond a complete, captured frame. */
        if (record.captured_length >= 14 &&
            parse_ethernet(record.data, record.captured_length, &ethernet) == PARSE_OK &&
            ethernet.ether_type == 0x0800u &&
            parse_ipv4(record.data + 14, record.captured_length - 14, &ip) == PARSE_OK &&
            record.captured_length == record.original_length &&
            ip.total_length > record.captured_length - 14u) {
            malformed_length = 1;
        }
        if (malformed_length) {
            (void)snprintf(report.text, sizeof(report.text),
                           "%u %u.%06u malformed IPv4",
                           (unsigned)frame_number,
                           (unsigned)(record.seconds - first_seconds),
                           (unsigned)record.microseconds);
        } else {
            (void)decode_frame(record.data, record.captured_length,
                               record.seconds - first_seconds,
                               record.microseconds, frame_number,
                               &flows, &report);
        }
        if (!summary_only) (void)fprintf(output, "%s\n", report.text);
    }

    if (flows.count != 0 && !summary_only) (void)fputc('\n', output);
    for (size_t i = 0; i < flows.count; ++i) {
        (void)fprintf(output, "%s %s <> %s packets=%u bytes=%llu\n",
                      flows.entries[i].protocol,
                      flows.entries[i].endpoint_a,
                      flows.entries[i].endpoint_b,
                      (unsigned)flows.entries[i].packets,
                      (unsigned long long)flows.entries[i].bytes);
    }
    flow_table_free(&flows);
    return 0;
}

/* Write both frame and flow reports. */
int report_capture(const PcapReader *source, FILE *output)
{
    return report_capture_mode(source, output, 0);
}

/* Initialize a pcap reader and report a complete capture supplied as bytes. */
int report_capture_bytes(const uint8_t *data, size_t length, FILE *output)
{
    PcapReader reader;
    PcapStatus status = pcap_reader_init(&reader, data, length);
    if (status != PCAP_OK) return -1;
    return report_capture(&reader, output);
}

/* Write only flow summary entries for an in-memory capture. */
int report_capture_bytes_summary(const uint8_t *data, size_t length, FILE *output)
{
    PcapReader reader;
    PcapStatus status = pcap_reader_init(&reader, data, length);
    if (status != PCAP_OK) return -1;
    return report_capture_mode(&reader, output, 1);
}
