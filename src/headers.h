#ifndef HEADERS_H
#define HEADERS_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    /* Result of a bounded header parse. */
    PARSE_OK = 0,
    PARSE_TRUNCATED = 1,
    PARSE_INVALID = 2
} ParseStatus;

typedef struct {
    /* Decoded 14-byte Ethernet II header. */
    uint8_t destination[6];
    uint8_t source[6];
    uint16_t ether_type;
} EthernetHeader;

typedef struct {
    /* Decoded Ethernet-address resolution protocol header. */
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_length;
    uint8_t protocol_length;
    uint16_t operation;
    uint8_t sender_hardware[6];
    uint8_t sender_protocol[4];
    uint8_t target_hardware[6];
    uint8_t target_protocol[4];
} ArpHeader;

typedef struct {
    /* Decoded IPv4 header and a bounded view of its payload. */
    uint8_t version;
    uint8_t ihl;
    uint8_t header_length;
    uint8_t dscp;
    uint8_t ecn;
    uint16_t total_length;
    uint16_t identification;
    uint8_t flags;
    uint16_t fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t source;
    uint32_t destination;
    const uint8_t *payload;
    size_t payload_length;
} Ipv4Header;

typedef struct {
    /* Decoded TCP header fields and the transport-header length. */
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence;
    uint32_t acknowledgement;
    uint8_t header_length;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
} TcpHeader;

typedef struct {
    /* Decoded UDP header fields. */
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;
} UdpHeader;

/* Parse Ethernet, ARP, and network-layer headers without I/O or allocation. */
ParseStatus parse_ethernet(const uint8_t *data, size_t length, EthernetHeader *out);
ParseStatus parse_arp(const uint8_t *data, size_t length, ArpHeader *out);
ParseStatus parse_ipv4(const uint8_t *data, size_t length, Ipv4Header *out);

/* Parse transport headers from exactly the available payload bytes. */
ParseStatus parse_tcp(const uint8_t *data, size_t length, TcpHeader *out);
ParseStatus parse_udp(const uint8_t *data, size_t length, UdpHeader *out);

/* Pure checksum and presentation helpers used by parsers and reporting. */
uint16_t internet_checksum(const uint8_t *data, size_t length);
void format_mac_address(const uint8_t address[6], char output[18]);
void format_ipv4_address(uint32_t address, char output[16]);
void format_tcp_flags(uint8_t flags, char output[32]);

/* Compatibility aliases retained for the alternate parser naming conventions. */
ParseStatus ethernet_parse(const uint8_t *data, size_t length, EthernetHeader *out);
ParseStatus arp_parse(const uint8_t *data, size_t length, ArpHeader *out);
ParseStatus ipv4_parse(const uint8_t *data, size_t length, Ipv4Header *out);
ParseStatus tcp_parse(const uint8_t *data, size_t length, TcpHeader *out);
ParseStatus udp_parse(const uint8_t *data, size_t length, UdpHeader *out);
ParseStatus parse_ethernet_header(const uint8_t *data, size_t length, EthernetHeader *out);
ParseStatus parse_arp_header(const uint8_t *data, size_t length, ArpHeader *out);
ParseStatus parse_ipv4_header(const uint8_t *data, size_t length, Ipv4Header *out);
ParseStatus parse_tcp_header(const uint8_t *data, size_t length, TcpHeader *out);
ParseStatus parse_udp_header(const uint8_t *data, size_t length, UdpHeader *out);
uint16_t checksum(const uint8_t *data, size_t length);
void mac_address_format(const uint8_t address[6], char output[18]);
void ipv4_address_format(uint32_t address, char output[16]);
void tcp_flags_format(uint8_t flags, char output[32]);

#endif
