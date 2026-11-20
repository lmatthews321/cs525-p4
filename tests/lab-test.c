#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "harness/unity.h"
#include "../src/headers.h"
#include "../src/pcap.h"
#include "../src/report.h"

int main_exclude(int argc, char **argv);

#define FRAME_BUFFER_SIZE 128u
#define PCAP_HEADER_SIZE 24u

void setUp(void) { }
void tearDown(void) { }

static void put_be16(uint8_t *p, uint16_t value)
{
  p[0] = (uint8_t)(value >> 8);
  p[1] = (uint8_t)value;
}

static void put_be32(uint8_t *p, uint32_t value)
{
  p[0] = (uint8_t)(value >> 24);
  p[1] = (uint8_t)(value >> 16);
  p[2] = (uint8_t)(value >> 8);
  p[3] = (uint8_t)value;
}

static uint16_t get_be16(const uint8_t *p)
{
  return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void put_file16(uint8_t *p, uint16_t value, int little_endian)
{
  if (little_endian) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
  } else {
    put_be16(p, value);
  }
}

static void put_file32(uint8_t *p, uint32_t value, int little_endian)
{
  if (little_endian) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
  } else {
    put_be32(p, value);
  }
}

static void make_pcap_header(uint8_t *capture, int little_endian)
{
  memset(capture, 0, PCAP_HEADER_SIZE);
  if (little_endian) {
    capture[0] = 0xd4;
    capture[1] = 0xc3;
    capture[2] = 0xb2;
    capture[3] = 0xa1;
  } else {
    capture[0] = 0xa1;
    capture[1] = 0xb2;
    capture[2] = 0xc3;
    capture[3] = 0xd4;
  }
  put_file16(capture + 4, 2, little_endian);
  put_file16(capture + 6, 4, little_endian);
  put_file32(capture + 16, 65535, little_endian);
  put_file32(capture + 20, 1, little_endian);
}

static size_t append_pcap_record(uint8_t *capture, int little_endian,
                                const uint8_t *frame, uint32_t captured_length,
                                uint32_t original_length)
{
  uint8_t *record = capture + PCAP_HEADER_SIZE;
  put_file32(record, 100, little_endian);
  put_file32(record + 4, 250000, little_endian);
  put_file32(record + 8, captured_length, little_endian);
  put_file32(record + 12, original_length, little_endian);
  if (captured_length != 0) {
    memcpy(record + 16, frame, captured_length);
  }
  return PCAP_HEADER_SIZE + 16u + (size_t)captured_length;
}

static size_t make_tcp_frame(uint8_t *frame, size_t ip_header_length,
                             size_t payload_length, uint32_t source,
                             uint32_t destination, uint16_t source_port,
                             uint16_t destination_port, uint8_t flags,
                             uint32_t sequence, uint32_t acknowledgement,
                             uint16_t window)
{
  memset(frame, 0, FRAME_BUFFER_SIZE);
  frame[12] = 0x08;
  frame[13] = 0x00;

  uint8_t *ip = frame + 14;
  ip[0] = (uint8_t)(0x40u | (uint8_t)(ip_header_length / 4u));
  put_be16(ip + 2, (uint16_t)(ip_header_length + 20u + payload_length));
  ip[8] = 64;
  ip[9] = 6;
  put_be32(ip + 12, source);
  put_be32(ip + 16, destination);
  uint8_t *tcp = ip + ip_header_length;
  put_be16(tcp, source_port);
  put_be16(tcp + 2, destination_port);
  put_be32(tcp + 4, sequence);
  put_be32(tcp + 8, acknowledgement);
  tcp[12] = 0x50;
  tcp[13] = flags;
  put_be16(tcp + 14, window);
  memset(tcp + 20, 0x42, payload_length);
  put_be16(ip + 10, internet_checksum(ip, ip_header_length));
  return 14u + ip_header_length + 20u + payload_length;
}

static void set_tcp_checksum(uint8_t *frame, size_t ip_header_length)
{
  uint8_t *ip = frame + 14;
  size_t segment_length = (size_t)get_be16(ip + 2) - ip_header_length;
  uint8_t pseudo_segment[12u + FRAME_BUFFER_SIZE] = {0};
  memcpy(pseudo_segment, ip + 12, 8);
  pseudo_segment[9] = ip[9];
  put_be16(pseudo_segment + 10, (uint16_t)segment_length);
  memcpy(pseudo_segment + 12, ip + ip_header_length, segment_length);
  put_be16(ip + ip_header_length + 16,
           internet_checksum(pseudo_segment, 12u + segment_length));
}

static void set_udp_checksum(uint8_t *frame)
{
  uint8_t *ip = frame + 14;
  size_t segment_length = (size_t)get_be16(ip + 2) - 20u;
  uint8_t pseudo_segment[12u + FRAME_BUFFER_SIZE] = {0};
  memcpy(pseudo_segment, ip + 12, 8);
  pseudo_segment[9] = ip[9];
  put_be16(pseudo_segment + 10, (uint16_t)segment_length);
  memcpy(pseudo_segment + 12, ip + 20, segment_length);
  uint16_t value = internet_checksum(pseudo_segment, 12u + segment_length);
  put_be16(ip + 20u + 6u, value == 0 ? 0xffffu : value);
}

static size_t make_udp_frame(uint8_t *frame, size_t payload_length,
                             uint32_t source, uint32_t destination,
                             uint16_t source_port, uint16_t destination_port)
{
  memset(frame, 0, FRAME_BUFFER_SIZE);
  frame[12] = 0x08;
  frame[13] = 0x00;
  uint8_t *ip = frame + 14;
  ip[0] = 0x45;
  put_be16(ip + 2, (uint16_t)(20u + 8u + payload_length));
  ip[8] = 64;
  ip[9] = 17;
  put_be32(ip + 12, source);
  put_be32(ip + 16, destination);
  uint8_t *udp = ip + 20;
  put_be16(udp, source_port);
  put_be16(udp + 2, destination_port);
  put_be16(udp + 4, (uint16_t)(8u + payload_length));
  memset(udp + 8, 0x24, payload_length);
  put_be16(ip + 10, internet_checksum(ip, 20));
  return 14u + 20u + 8u + payload_length;
}

static void make_arp_payload(uint8_t payload[28])
{
  memset(payload, 0, 28);
  put_be16(payload, 1);
  put_be16(payload + 2, 0x0800);
  payload[4] = 6;
  payload[5] = 4;
  put_be16(payload + 6, 1);
  payload[8] = 0x00;
  payload[9] = 0x11;
  payload[10] = 0x22;
  payload[11] = 0x33;
  payload[12] = 0x44;
  payload[13] = 0x55;
  payload[14] = 10;
  payload[17] = 1;
  payload[24] = 10;
  payload[27] = 2;
}

static void assert_file_output(FILE *file, const char *expected)
{
  TEST_ASSERT_NOT_NULL(file);
  if (file == NULL) return;
  TEST_ASSERT_EQUAL_INT(0, fflush(file));
  rewind(file);
  char output[1024];
  size_t length = fread(output, 1, sizeof(output) - 1u, file);
  TEST_ASSERT_FALSE(ferror(file));
  output[length] = '\0';
  TEST_ASSERT_EQUAL_STRING(expected, output);
  fclose(file);
}

static void run_main_and_assert_output(int argc, char **argv,
                                       const char *expected)
{
  /* Capture stdout temporarily so main() can be tested through Unity. */
  FILE *output = tmpfile();
  TEST_ASSERT_NOT_NULL(output);
  if (output == NULL) return;
  int saved_stdout = dup(STDOUT_FILENO);
  TEST_ASSERT_TRUE(saved_stdout >= 0);
  if (saved_stdout < 0) {
    fclose(output);
    return;
  }
  TEST_ASSERT_EQUAL_INT(0, fflush(stdout));
  TEST_ASSERT_EQUAL_INT(STDOUT_FILENO, dup2(fileno(output), STDOUT_FILENO));
  int result = main_exclude(argc, argv);
  TEST_ASSERT_EQUAL_INT(0, fflush(stdout));
  TEST_ASSERT_EQUAL_INT(STDOUT_FILENO, dup2(saved_stdout, STDOUT_FILENO));
  TEST_ASSERT_EQUAL_INT(0, close(saved_stdout));
  TEST_ASSERT_EQUAL_INT(0, result);
  assert_file_output(output, expected);
}

static void test_pcap_byte_orders(void)
{
  const uint8_t payload[] = {0xde, 0xad, 0xbe, 0xef};
  uint8_t capture[PCAP_HEADER_SIZE + 16u + sizeof(payload)];
  for (int little_endian = 0; little_endian <= 1; ++little_endian) {
    make_pcap_header(capture, little_endian);
    size_t length = append_pcap_record(capture, little_endian, payload,
                                       sizeof(payload), sizeof(payload));
    PcapReader reader;
    PcapRecord record;
    TEST_ASSERT_EQUAL(PCAP_OK, pcap_reader_init(&reader, capture, length));
    TEST_ASSERT_EQUAL_INT(little_endian, reader.little_endian);
    TEST_ASSERT_EQUAL(PCAP_OK, pcap_reader_next(&reader, &record));
    TEST_ASSERT_EQUAL_UINT32(100, record.seconds);
    TEST_ASSERT_EQUAL_UINT32(250000, record.microseconds);
    TEST_ASSERT_EQUAL_UINT32(sizeof(payload), record.captured_length);
    TEST_ASSERT_EQUAL_UINT32(sizeof(payload), record.original_length);
    TEST_ASSERT_EQUAL_MEMORY(payload, record.data, sizeof(payload));
    TEST_ASSERT_EQUAL(PCAP_END, pcap_reader_next(&reader, &record));
  }
}

static void test_pcap_malformed_and_truncated_files(void)
{
  uint8_t valid_header[PCAP_HEADER_SIZE];
  PcapReader reader;
  make_pcap_header(valid_header, 1);

  const uint8_t short_global_header[23] = {0};
  TEST_ASSERT_EQUAL(PCAP_TRUNCATED,
                    pcap_reader_init(&reader, short_global_header,
                                     sizeof(short_global_header)));
  TEST_ASSERT_EQUAL(PCAP_INVALID, pcap_reader_init(&reader, NULL, 24));
  TEST_ASSERT_EQUAL(PCAP_INVALID, pcap_reader_init(NULL, valid_header, 24));

  uint8_t bad_magic[PCAP_HEADER_SIZE];
  memcpy(bad_magic, valid_header, sizeof(bad_magic));
  bad_magic[0] = 0;
  TEST_ASSERT_EQUAL(PCAP_INVALID,
                    pcap_reader_init(&reader, bad_magic, sizeof(bad_magic)));

  uint8_t bad_version[PCAP_HEADER_SIZE];
  memcpy(bad_version, valid_header, sizeof(bad_version));
  put_file16(bad_version + 4, 3, 1);
  TEST_ASSERT_EQUAL(PCAP_INVALID,
                    pcap_reader_init(&reader, bad_version, sizeof(bad_version)));

  uint8_t bad_minor_version[PCAP_HEADER_SIZE];
  memcpy(bad_minor_version, valid_header, sizeof(bad_minor_version));
  put_file16(bad_minor_version + 6, 5, 1);
  TEST_ASSERT_EQUAL(PCAP_INVALID,
                    pcap_reader_init(&reader, bad_minor_version,
                                     sizeof(bad_minor_version)));

  uint8_t bad_linktype[PCAP_HEADER_SIZE];
  memcpy(bad_linktype, valid_header, sizeof(bad_linktype));
  put_file32(bad_linktype + 20, 101, 1);
  TEST_ASSERT_EQUAL(PCAP_INVALID,
                    pcap_reader_init(&reader, bad_linktype, sizeof(bad_linktype)));

  uint8_t short_record_header[PCAP_HEADER_SIZE + 15u] = {0};
  make_pcap_header(short_record_header, 1);
  TEST_ASSERT_EQUAL(PCAP_OK,
                    pcap_reader_init(&reader, short_record_header,
                                     sizeof(short_record_header)));
  PcapRecord record;
  TEST_ASSERT_EQUAL(PCAP_TRUNCATED, pcap_reader_next(&reader, &record));

  uint8_t short_record_data[PCAP_HEADER_SIZE + 16u + 3u] = {0};
  make_pcap_header(short_record_data, 1);
  put_file32(short_record_data + PCAP_HEADER_SIZE + 8u, 4, 1);
  put_file32(short_record_data + PCAP_HEADER_SIZE + 12u, 4, 1);
  TEST_ASSERT_EQUAL(PCAP_OK,
                    pcap_reader_init(&reader, short_record_data,
                                     sizeof(short_record_data)));
  TEST_ASSERT_EQUAL(PCAP_TRUNCATED, pcap_reader_next(&reader, &record));
  TEST_ASSERT_EQUAL(PCAP_INVALID, pcap_reader_next(NULL, &record));
  TEST_ASSERT_EQUAL(PCAP_INVALID, pcap_reader_next(&reader, NULL));
  PcapReader invalid_reader = {0};
  TEST_ASSERT_EQUAL(PCAP_INVALID, pcap_reader_next(&invalid_reader, &record));
}

static void test_valid_header_parsers_and_aliases(void)
{
  const uint8_t ethernet_bytes[14] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 8, 0
  };
  EthernetHeader ethernet;
  TEST_ASSERT_EQUAL(PARSE_OK, parse_ethernet(ethernet_bytes,
                                              sizeof(ethernet_bytes), &ethernet));
  TEST_ASSERT_EQUAL_UINT16(0x0800, ethernet.ether_type);
  TEST_ASSERT_EQUAL(PARSE_OK, ethernet_parse(ethernet_bytes,
                                              sizeof(ethernet_bytes), &ethernet));
  TEST_ASSERT_EQUAL(PARSE_OK, parse_ethernet_header(ethernet_bytes,
                                                    sizeof(ethernet_bytes),
                                                    &ethernet));

  uint8_t arp_bytes[28];
  make_arp_payload(arp_bytes);
  ArpHeader arp;
  TEST_ASSERT_EQUAL(PARSE_OK, parse_arp(arp_bytes, sizeof(arp_bytes), &arp));
  TEST_ASSERT_EQUAL_UINT16(1, arp.operation);
  TEST_ASSERT_EQUAL(PARSE_OK, arp_parse(arp_bytes, sizeof(arp_bytes), &arp));
  TEST_ASSERT_EQUAL(PARSE_OK, parse_arp_header(arp_bytes, sizeof(arp_bytes), &arp));

  uint8_t frame[FRAME_BUFFER_SIZE];
  size_t frame_length = make_tcp_frame(frame, 20, 0, 0x0a000001u, 0x0a000002u,
                                       1234, 80, 0x12, 1, 2, 4096);
  Ipv4Header ip;
  TEST_ASSERT_EQUAL(PARSE_OK, parse_ipv4(frame + 14, frame_length - 14, &ip));
  TEST_ASSERT_EQUAL_UINT32(0x0a000001u, ip.source);
  TEST_ASSERT_EQUAL(PARSE_OK, ipv4_parse(frame + 14, frame_length - 14, &ip));
  TEST_ASSERT_EQUAL(PARSE_OK, parse_ipv4_header(frame + 14,
                                                 frame_length - 14, &ip));

  TcpHeader tcp;
  TEST_ASSERT_EQUAL(PARSE_OK, parse_tcp(ip.payload, ip.payload_length, &tcp));
  TEST_ASSERT_EQUAL_UINT16(1234, tcp.source_port);
  TEST_ASSERT_EQUAL(PARSE_OK, tcp_parse(ip.payload, ip.payload_length, &tcp));
  TEST_ASSERT_EQUAL(PARSE_OK, parse_tcp_header(ip.payload,
                                                ip.payload_length, &tcp));

  frame_length = make_udp_frame(frame, 2, 0x0a000001u, 0x0a000002u, 5353, 53);
  TEST_ASSERT_EQUAL(PARSE_OK, parse_ipv4(frame + 14, frame_length - 14, &ip));
  UdpHeader udp;
  TEST_ASSERT_EQUAL(PARSE_OK, parse_udp(ip.payload, ip.payload_length, &udp));
  TEST_ASSERT_EQUAL_UINT16(5353, udp.source_port);
  TEST_ASSERT_EQUAL(PARSE_OK, udp_parse(ip.payload, ip.payload_length, &udp));
  TEST_ASSERT_EQUAL(PARSE_OK, parse_udp_header(ip.payload,
                                                ip.payload_length, &udp));
}

static void test_malformed_header_parsers(void)
{
  EthernetHeader ethernet;
  const uint8_t short_ethernet[13] = {0};
  TEST_ASSERT_EQUAL(PARSE_TRUNCATED,
                    parse_ethernet(short_ethernet, sizeof(short_ethernet), &ethernet));
  TEST_ASSERT_EQUAL(PARSE_INVALID, parse_ethernet(NULL, 14, &ethernet));
  TEST_ASSERT_EQUAL(PARSE_INVALID, parse_ethernet(short_ethernet, 14, NULL));

  uint8_t valid_arp[28];
  make_arp_payload(valid_arp);
  ArpHeader arp;
  const uint8_t short_arp[27] = {0};
  TEST_ASSERT_EQUAL(PARSE_TRUNCATED, parse_arp(short_arp, sizeof(short_arp), &arp));
  uint8_t bad_hardware_type[28];
  uint8_t bad_protocol_type[28];
  uint8_t bad_hardware_length[28];
  uint8_t bad_protocol_length[28];
  memcpy(bad_hardware_type, valid_arp, 28);
  memcpy(bad_protocol_type, valid_arp, 28);
  memcpy(bad_hardware_length, valid_arp, 28);
  memcpy(bad_protocol_length, valid_arp, 28);
  bad_hardware_type[1] = 2;
  bad_protocol_type[2] = 0x86;
  bad_hardware_length[4] = 5;
  bad_protocol_length[5] = 3;
  TEST_ASSERT_EQUAL(PARSE_INVALID,
                    parse_arp(bad_hardware_type, sizeof(bad_hardware_type), &arp));
  TEST_ASSERT_EQUAL(PARSE_INVALID,
                    parse_arp(bad_protocol_type, sizeof(bad_protocol_type), &arp));
  TEST_ASSERT_EQUAL(PARSE_INVALID,
                    parse_arp(bad_hardware_length, sizeof(bad_hardware_length), &arp));
  TEST_ASSERT_EQUAL(PARSE_INVALID,
                    parse_arp(bad_protocol_length, sizeof(bad_protocol_length), &arp));
  TEST_ASSERT_EQUAL(PARSE_INVALID, parse_arp(NULL, 28, &arp));
  TEST_ASSERT_EQUAL(PARSE_INVALID, parse_arp(valid_arp, 28, NULL));

  const uint8_t short_ipv4[19] = {0};
  const uint8_t bad_ipv4_version[20] = {0x65};
  const uint8_t bad_ipv4_ihl[20] = {0x44};
  const uint8_t bad_ipv4_option_length[20] = {0x46};
  uint8_t bad_ipv4_total_length[20] = {0x45};
  put_be16(bad_ipv4_total_length + 2, 19);
  Ipv4Header ip;
  TEST_ASSERT_EQUAL(PARSE_TRUNCATED, parse_ipv4(short_ipv4, sizeof(short_ipv4), &ip));
  TEST_ASSERT_EQUAL(PARSE_INVALID, parse_ipv4(bad_ipv4_version, 20, &ip));
  TEST_ASSERT_EQUAL(PARSE_INVALID, parse_ipv4(bad_ipv4_ihl, 20, &ip));
  TEST_ASSERT_EQUAL(PARSE_INVALID, parse_ipv4(bad_ipv4_option_length, 20, &ip));
  TEST_ASSERT_EQUAL(PARSE_INVALID, parse_ipv4(bad_ipv4_total_length, 20, &ip));
  TEST_ASSERT_EQUAL(PARSE_INVALID, parse_ipv4(NULL, 20, &ip));
  TEST_ASSERT_EQUAL(PARSE_INVALID, parse_ipv4(short_ipv4, 20, NULL));

  const uint8_t short_tcp[19] = {0};
  uint8_t bad_tcp_small_header[20] = {0};
  uint8_t bad_tcp_long_header[20] = {0};
  bad_tcp_small_header[12] = 0x40;
  bad_tcp_long_header[12] = 0x60;
  TcpHeader tcp;
  TEST_ASSERT_EQUAL(PARSE_TRUNCATED, parse_tcp(short_tcp, sizeof(short_tcp), &tcp));
  TEST_ASSERT_EQUAL(PARSE_INVALID, parse_tcp(bad_tcp_small_header, 20, &tcp));
  TEST_ASSERT_EQUAL(PARSE_INVALID, parse_tcp(bad_tcp_long_header, 20, &tcp));
  TEST_ASSERT_EQUAL(PARSE_INVALID, parse_tcp(NULL, 20, &tcp));
  TEST_ASSERT_EQUAL(PARSE_INVALID, parse_tcp(short_tcp, 20, NULL));

  const uint8_t short_udp[7] = {0};
  uint8_t bad_udp_length[8] = {0};
  put_be16(bad_udp_length + 4, 7);
  UdpHeader udp;
  TEST_ASSERT_EQUAL(PARSE_TRUNCATED, parse_udp(short_udp, sizeof(short_udp), &udp));
  TEST_ASSERT_EQUAL(PARSE_INVALID, parse_udp(bad_udp_length, 8, &udp));
  TEST_ASSERT_EQUAL(PARSE_INVALID, parse_udp(NULL, 8, &udp));
  TEST_ASSERT_EQUAL(PARSE_INVALID, parse_udp(short_udp, 8, NULL));
}

static void test_checksum_and_format_helpers(void)
{
  const uint8_t odd_bytes[] = {0x01, 0x02, 0x03};
  const uint8_t repeated_carries[] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x01};
  TEST_ASSERT_EQUAL_UINT16(0xfbfd, internet_checksum(odd_bytes, sizeof(odd_bytes)));
  TEST_ASSERT_EQUAL_UINT16(0xfffe,
                           internet_checksum(repeated_carries,
                                             sizeof(repeated_carries)));
  TEST_ASSERT_EQUAL_UINT16(internet_checksum(odd_bytes, sizeof(odd_bytes)),
                           checksum(odd_bytes, sizeof(odd_bytes)));
  TEST_ASSERT_EQUAL_UINT16(0, internet_checksum(NULL, sizeof(odd_bytes)));

  const uint8_t mac[] = {0x00, 0x11, 0xaa, 0xbb, 0xcc, 0xff};
  char mac_text[18];
  format_mac_address(mac, mac_text);
  TEST_ASSERT_EQUAL_STRING("00:11:aa:bb:cc:ff", mac_text);
  mac_address_format(mac, mac_text);
  TEST_ASSERT_EQUAL_STRING("00:11:aa:bb:cc:ff", mac_text);
  format_mac_address(NULL, mac_text);
  TEST_ASSERT_EQUAL_STRING("", mac_text);
  format_mac_address(mac, NULL);

  char ip_text[16];
  format_ipv4_address(0x40e9a969u, ip_text);
  TEST_ASSERT_EQUAL_STRING("64.233.169.105", ip_text);
  ipv4_address_format(0x40e9a969u, ip_text);
  TEST_ASSERT_EQUAL_STRING("64.233.169.105", ip_text);
  format_ipv4_address(0, NULL);

  char flags[32];
  format_tcp_flags(0, flags);
  TEST_ASSERT_EQUAL_STRING("none", flags);
  format_tcp_flags(0x11u, flags);
  TEST_ASSERT_EQUAL_STRING("F.", flags);
  format_tcp_flags(0x12u, flags);
  TEST_ASSERT_EQUAL_STRING("S.", flags);
  format_tcp_flags(0xffu, flags);
  TEST_ASSERT_EQUAL_STRING("FSRPUEW.", flags);
  tcp_flags_format(0x12u, flags);
  TEST_ASSERT_EQUAL_STRING("S.", flags);
  format_tcp_flags(0, NULL);
}

static void test_decode_ipv4_options_padding_and_tcp_flags(void)
{
  uint8_t frame[FRAME_BUFFER_SIZE];
  size_t frame_length = make_tcp_frame(frame, 24, 0, 0x40e9a969u, 0x44550265u,
                                       80, 49152, 0x12, 2215467233u,
                                       3127851021u, 1050);
  set_tcp_checksum(frame, 24);
  memset(frame + frame_length, 0xaa, 8);

  FrameReport report;
  TEST_ASSERT_EQUAL(PARSE_OK,
                    decode_frame(frame, frame_length + 8u, 0, 68433, 11,
                                 NULL, &report));
  TEST_ASSERT_EQUAL_STRING(
    "11 0.068433 TCP 64.233.169.105:80 > 68.85.2.101:49152 [S.] "
    "seq=2215467233 ack=3127851021 win=1050 len=0 cksum=ok",
    report.text);
  TEST_ASSERT_EQUAL(PARSE_INVALID,
                    decode_frame(frame, frame_length, 0, 0, 0, NULL, NULL));
}

static void test_decode_snaplen_and_tcp_checksum_status(void)
{
  uint8_t frame[FRAME_BUFFER_SIZE];
  size_t frame_length = make_tcp_frame(frame, 20, 3, 0x0a000001u, 0x0a000002u,
                                       1234, 80, 0x10, 1, 2, 4096);
  set_tcp_checksum(frame, 20);
  FrameReport report;
  TEST_ASSERT_EQUAL(PARSE_OK,
                    decode_frame(frame, frame_length, 0, 0, 1, NULL, &report));
  TEST_ASSERT_TRUE(strstr(report.text, "cksum=ok") != NULL);
  TEST_ASSERT_EQUAL(PARSE_OK,
                    decode_frame(frame, frame_length - 1u, 0, 0, 1,
                                 NULL, &report));
  TEST_ASSERT_TRUE(strstr(report.text, "len=2 cksum=bad") != NULL);

  frame[14u + 20u + 16u] ^= 0x01;
  TEST_ASSERT_EQUAL(PARSE_OK,
                    decode_frame(frame, frame_length, 0, 0, 1, NULL, &report));
  TEST_ASSERT_TRUE(strstr(report.text, "cksum=bad") != NULL);
}

static void test_decode_arp_udp_fragments_and_malformed_frames(void)
{
  uint8_t frame[FRAME_BUFFER_SIZE];
  uint8_t arp_payload[28];
  make_arp_payload(arp_payload);
  memset(frame, 0, sizeof(frame));
  frame[12] = 0x08;
  frame[13] = 0x06;
  memcpy(frame + 14, arp_payload, sizeof(arp_payload));

  FrameReport report;
  TEST_ASSERT_EQUAL(PARSE_OK,
                    decode_frame(frame, 42, 0, 0, 1, NULL, &report));
  TEST_ASSERT_EQUAL_STRING(
      "1 0.000000 ARP request who-has 10.0.0.2 tell 10.0.0.1",
      report.text);

  put_be16(arp_payload + 6, 2);
  memcpy(frame + 14, arp_payload, sizeof(arp_payload));
  TEST_ASSERT_EQUAL(PARSE_OK,
                    decode_frame(frame, 42, 0, 0, 2, NULL, &report));
  TEST_ASSERT_EQUAL_STRING(
      "2 0.000000 ARP reply 10.0.0.1 is-at 00:11:22:33:44:55",
      report.text);

  put_be16(arp_payload + 6, 3);
  memcpy(frame + 14, arp_payload, sizeof(arp_payload));
  TEST_ASSERT_EQUAL(PARSE_OK,
                    decode_frame(frame, 42, 0, 0, 3, NULL, &report));
  TEST_ASSERT_EQUAL_STRING("3 0.000000 ARP op=3", report.text);

  TEST_ASSERT_EQUAL(PARSE_TRUNCATED,
                    decode_frame(frame, 41, 0, 0, 1, NULL, &report));
  TEST_ASSERT_TRUE(strstr(report.text, "malformed ARP") != NULL);

  frame[12] = 0x12;
  frame[13] = 0x34;
  TEST_ASSERT_EQUAL(PARSE_OK,
                    decode_frame(frame, 42, 0, 0, 4, NULL, &report));
  TEST_ASSERT_EQUAL_STRING("4 0.000000 Ethernet type=0x1234", report.text);
  TEST_ASSERT_EQUAL(PARSE_TRUNCATED,
                    decode_frame(frame, 13, 0, 0, 4, NULL, &report));
  TEST_ASSERT_EQUAL(PARSE_INVALID,
                    decode_frame(NULL, 0, 0, 0, 4, NULL, &report));

  size_t frame_length = make_tcp_frame(frame, 20, 0, 0x0a000001u, 0x0a000002u,
                                       1234, 80, 0x02, 1, 0, 4096);
  frame[14u + 6u] = 0x20;
  TEST_ASSERT_EQUAL(PARSE_OK,
                    decode_frame(frame, frame_length, 0, 0, 3, NULL, &report));
  TEST_ASSERT_TRUE(strstr(report.text, "proto=6 fragment") != NULL);

  frame_length = make_tcp_frame(frame, 20, 0, 0x0a000001u, 0x0a000002u,
                                1234, 80, 0x02, 1, 0, 4096);
  frame[14u + 7u] = 0x01;
  TEST_ASSERT_EQUAL(PARSE_OK,
                    decode_frame(frame, frame_length, 0, 0, 4, NULL, &report));
  TEST_ASSERT_TRUE(strstr(report.text, "proto=6 fragment") != NULL);

  frame_length = make_tcp_frame(frame, 20, 0, 0x0a000001u, 0x0a000002u,
                                1234, 80, 0x02, 1, 0, 4096);
  frame[14u + 10u] ^= 0x01;
  TEST_ASSERT_EQUAL(PARSE_OK,
                    decode_frame(frame, frame_length, 0, 0, 5, NULL, &report));
  TEST_ASSERT_EQUAL_STRING(
    "5 0.000000 IPv4 10.0.0.1 > 10.0.0.2 proto=6 bad-header-cksum",
    report.text);

  uint8_t malformed_ipv4[14u + 20u] = {0};
  malformed_ipv4[12] = 0x08;
  malformed_ipv4[13] = 0;
  malformed_ipv4[14] = 0x44;
  TEST_ASSERT_EQUAL(PARSE_INVALID,
                    decode_frame(malformed_ipv4, sizeof(malformed_ipv4),
                                 0, 0, 5, NULL, &report));
  TEST_ASSERT_TRUE(strstr(report.text, "malformed IPv4") != NULL);

  frame_length = make_udp_frame(frame, 2, 0x0a000001u, 0x0a000002u, 5353, 53);
  TEST_ASSERT_EQUAL(PARSE_OK,
                    decode_frame(frame, frame_length, 0, 3, 1, NULL, &report));
  TEST_ASSERT_TRUE(strstr(report.text, "cksum=none") != NULL);
  set_udp_checksum(frame);
  FlowTable udp_flows;
  flow_table_init(&udp_flows);
  TEST_ASSERT_EQUAL(PARSE_OK,
                    decode_frame(frame, frame_length, 0, 3, 1,
                                 &udp_flows, &report));
  TEST_ASSERT_EQUAL_STRING(
    "1 0.000003 UDP 10.0.0.1:5353 > 10.0.0.2:53 len=2 cksum=ok",
    report.text);
  TEST_ASSERT_EQUAL_UINT32(1, udp_flows.count);
  TEST_ASSERT_EQUAL_UINT32(1, udp_flows.entries[0].packets);

  frame[14u + 20u + 6u] ^= 0x01;
  TEST_ASSERT_EQUAL(PARSE_OK,
                    decode_frame(frame, frame_length, 0, 3, 2,
                                 &udp_flows, &report));
  TEST_ASSERT_TRUE(strstr(report.text, "cksum=bad") != NULL);
  TEST_ASSERT_EQUAL_UINT32(2, udp_flows.entries[0].packets);
  flow_table_free(&udp_flows);

  frame[14u + 9u] = 1;
  put_be16(frame + 14u + 10u, 0);
  put_be16(frame + 14u + 10u, internet_checksum(frame + 14, 20));
  TEST_ASSERT_EQUAL(PARSE_OK,
                    decode_frame(frame, frame_length, 0, 0, 1, NULL, &report));
  TEST_ASSERT_TRUE(strstr(report.text, "proto=1") != NULL);

  frame_length = make_tcp_frame(frame, 20, 0, 0x0a000001u, 0x0a000002u,
                                1234, 80, 0x02, 1, 0, 4096);
  frame[14u + 20u + 12u] = 0x40;
  TEST_ASSERT_EQUAL(PARSE_INVALID,
                    decode_frame(frame, frame_length, 0, 0, 1, NULL, &report));
  TEST_ASSERT_TRUE(strstr(report.text, "malformed TCP") != NULL);

  frame_length = make_udp_frame(frame, 0, 0x0a000001u, 0x0a000002u, 1234, 53);
  put_be16(frame + 14u + 20u + 4u, 7);
  TEST_ASSERT_EQUAL(PARSE_INVALID,
                    decode_frame(frame, frame_length, 0, 0, 1, NULL, &report));
  TEST_ASSERT_TRUE(strstr(report.text, "malformed UDP") != NULL);

  frame_length = make_udp_frame(frame, 0, 0x0a000001u, 0x0a000002u, 1234, 53);
  put_be16(frame + 14u + 20u + 4u, 12);
  TEST_ASSERT_EQUAL(PARSE_INVALID,
                    decode_frame(frame, frame_length, 0, 0, 1, NULL, &report));
  TEST_ASSERT_TRUE(strstr(report.text, "malformed UDP") != NULL);
}

static void test_bidirectional_flows_and_table_lifecycle(void)
{
  FlowTable flows;
  flow_table_init(&flows);
  TEST_ASSERT_EQUAL_UINT32(0, flows.count);
  TEST_ASSERT_EQUAL_UINT32(0, flows.capacity);

  uint8_t frame[FRAME_BUFFER_SIZE];
  FrameReport report;
  size_t frame_length = make_tcp_frame(frame, 20, 0, 0x0a000001u, 0x0a000002u,
                                       1234, 80, 0x02, 1, 0, 4096);
  TEST_ASSERT_EQUAL(PARSE_OK,
                    decode_frame(frame, frame_length, 0, 0, 1, &flows, &report));
  frame_length = make_tcp_frame(frame, 20, 0, 0x0a000002u, 0x0a000001u,
                                80, 1234, 0x12, 2, 1, 4096);
  TEST_ASSERT_EQUAL(PARSE_OK,
                    decode_frame(frame, frame_length, 0, 0, 2, &flows, &report));
  TEST_ASSERT_EQUAL_UINT32(1, flows.count);
  TEST_ASSERT_EQUAL_UINT32(2, flows.entries[0].packets);
  TEST_ASSERT_TRUE(flows.entries[0].bytes == (uint64_t)(frame_length * 2u));
  TEST_ASSERT_EQUAL_UINT32(0x0a000001u, flows.entries[0].address_a);
  TEST_ASSERT_EQUAL_UINT32(0x0a000002u, flows.entries[0].address_b);
  TEST_ASSERT_EQUAL_STRING("10.0.0.1:1234", flows.entries[0].endpoint_a);
  TEST_ASSERT_EQUAL_STRING("10.0.0.2:80", flows.entries[0].endpoint_b);

  frame_length = make_tcp_frame(frame, 20, 0, 0x0a000003u, 0x0a000003u,
                                80, 4000, 0x02, 3, 0, 4096);
  TEST_ASSERT_EQUAL(PARSE_OK,
                    decode_frame(frame, frame_length, 0, 0, 3, &flows, &report));
  frame_length = make_tcp_frame(frame, 20, 0, 0x0a000003u, 0x0a000003u,
                                4000, 80, 0x12, 4, 3, 4096);
  TEST_ASSERT_EQUAL(PARSE_OK,
                    decode_frame(frame, frame_length, 0, 0, 4, &flows, &report));
  TEST_ASSERT_EQUAL_UINT32(2, flows.count);
  TEST_ASSERT_EQUAL_UINT16(80, flows.entries[1].port_a);
  TEST_ASSERT_EQUAL_UINT16(4000, flows.entries[1].port_b);
  flow_table_free(&flows);
  TEST_ASSERT_EQUAL_UINT32(0, flows.count);
  TEST_ASSERT_EQUAL_UINT32(0, flows.capacity);
  TEST_ASSERT_NULL(flows.entries);
  flow_table_init(NULL);
  flow_table_free(NULL);
}

static void test_report_capture_entry_points_and_snaplen(void)
{
  uint8_t frame[FRAME_BUFFER_SIZE];
  size_t frame_length = make_tcp_frame(frame, 20, 2, 0x0a000001u, 0x0a000002u,
                                       1234, 80, 0x10, 1, 2, 4096);
  size_t captured_length = frame_length - 1u;
  uint8_t capture[PCAP_HEADER_SIZE + 16u + FRAME_BUFFER_SIZE];
  make_pcap_header(capture, 1);
  size_t capture_length = append_pcap_record(capture, 1, frame,
                                             (uint32_t)captured_length,
                                             (uint32_t)frame_length);
  PcapReader reader;
  TEST_ASSERT_EQUAL(PCAP_OK, pcap_reader_init(&reader, capture, capture_length));

  FILE *output = tmpfile();
  TEST_ASSERT_EQUAL_INT(0, report_capture(&reader, output));
  assert_file_output(output,
    "1 0.250000 TCP 10.0.0.1:1234 > 10.0.0.2:80 [.] "
    "seq=1 ack=2 win=4096 len=1 cksum=none\n\n"
    "TCP 10.0.0.1:1234 <> 10.0.0.2:80 packets=1 bytes=55\n");

  output = tmpfile();
  TEST_ASSERT_EQUAL_INT(0, report_capture_bytes(capture, capture_length, output));
  assert_file_output(output,
    "1 0.250000 TCP 10.0.0.1:1234 > 10.0.0.2:80 [.] "
    "seq=1 ack=2 win=4096 len=1 cksum=none\n\n"
    "TCP 10.0.0.1:1234 <> 10.0.0.2:80 packets=1 bytes=55\n");

  output = tmpfile();
  TEST_ASSERT_EQUAL_INT(0,
                        report_capture_bytes_summary(capture, capture_length,
                                                      output));
  assert_file_output(output,
    "TCP 10.0.0.1:1234 <> 10.0.0.2:80 packets=1 bytes=55\n");

  TEST_ASSERT_EQUAL_INT(-1, report_capture(NULL, stdout));
  TEST_ASSERT_EQUAL_INT(-1, report_capture(&reader, NULL));
  TEST_ASSERT_EQUAL_INT(-1, report_capture_bytes(NULL, 0, stdout));
  TEST_ASSERT_EQUAL_INT(-1, report_capture_bytes_summary(NULL, 0, stdout));
  PcapReader invalid_reader = {0};
  output = tmpfile();
  TEST_ASSERT_EQUAL_INT(-1, report_capture(&invalid_reader, output));
  fclose(output);
}

static void test_report_capture_both_byte_orders_and_trailing_truncation(void)
{
  const uint8_t frame[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x12, 0x34};
  uint8_t capture[PCAP_HEADER_SIZE + 16u + sizeof(frame)];
  for (int little_endian = 0; little_endian <= 1; ++little_endian) {
    make_pcap_header(capture, little_endian);
    size_t length = append_pcap_record(capture, little_endian, frame,
                                       sizeof(frame), sizeof(frame));
    FILE *output = tmpfile();
    TEST_ASSERT_EQUAL_INT(0, report_capture_bytes(capture, length, output));
    assert_file_output(output, "1 0.250000 Ethernet type=0x1234\n");

    output = tmpfile();
    TEST_ASSERT_EQUAL_INT(0, report_capture_bytes(capture, length - 1u, output));
    assert_file_output(output, "");
  }

  uint8_t malformed_frame[FRAME_BUFFER_SIZE];
  size_t malformed_length = make_tcp_frame(
    malformed_frame, 20, 0, 0x0a000001u, 0x0a000002u, 1234, 80, 0x02, 1, 0, 4096);
  put_be16(malformed_frame + 14u + 2u, 100);
  put_be16(malformed_frame + 14u + 10u, 0);
  put_be16(malformed_frame + 14u + 10u,
           internet_checksum(malformed_frame + 14, 20));
  uint8_t malformed_capture[PCAP_HEADER_SIZE + 16u + FRAME_BUFFER_SIZE];
  make_pcap_header(malformed_capture, 1);
  size_t malformed_capture_length = append_pcap_record(
    malformed_capture, 1, malformed_frame, (uint32_t)malformed_length,
    (uint32_t)malformed_length);
  FILE *output = tmpfile();
  TEST_ASSERT_EQUAL_INT(
    0, report_capture_bytes(malformed_capture, malformed_capture_length, output));
  assert_file_output(output, "1 0.250000 malformed IPv4\n");
}

static void test_main_getopt_capture_arguments(void)
{
  /* Exercise both normal and -s argument paths with a real temporary capture. */
  char path[] = "/tmp/cs525-p4-unity-XXXXXX";
  int descriptor = mkstemp(path);
  TEST_ASSERT_TRUE(descriptor >= 0);
  if (descriptor < 0) return;

  const uint8_t frame[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x12, 0x34
  };
  uint8_t capture[PCAP_HEADER_SIZE + 16u + sizeof(frame)];
  make_pcap_header(capture, 1);
  size_t capture_length = append_pcap_record(capture, 1, frame,
                                             sizeof(frame), sizeof(frame));
  FILE *file = fdopen(descriptor, "wb");
  TEST_ASSERT_NOT_NULL(file);
  if (file == NULL) {
    close(descriptor);
    unlink(path);
    return;
  }
  size_t written = fwrite(capture, 1, capture_length, file);
  int close_status = fclose(file);
  TEST_ASSERT_EQUAL(capture_length, written);
  TEST_ASSERT_EQUAL_INT(0, close_status);

  char *default_arguments[] = {"myapp", path, NULL};
  optind = 1;
  run_main_and_assert_output(2, default_arguments,
                             "1 0.250000 Ethernet type=0x1234\n");

  char *summary_arguments[] = {"myapp", "-s", path, NULL};
  optind = 1;
  run_main_and_assert_output(3, summary_arguments, "");
  TEST_ASSERT_EQUAL_INT(0, unlink(path));
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_pcap_byte_orders);
  RUN_TEST(test_pcap_malformed_and_truncated_files);
  RUN_TEST(test_valid_header_parsers_and_aliases);
  RUN_TEST(test_malformed_header_parsers);
  RUN_TEST(test_checksum_and_format_helpers);
  RUN_TEST(test_decode_ipv4_options_padding_and_tcp_flags);
  RUN_TEST(test_decode_snaplen_and_tcp_checksum_status);
  RUN_TEST(test_decode_arp_udp_fragments_and_malformed_frames);
  RUN_TEST(test_bidirectional_flows_and_table_lifecycle);
  RUN_TEST(test_report_capture_entry_points_and_snaplen);
  RUN_TEST(test_report_capture_both_byte_orders_and_trailing_truncation);
  RUN_TEST(test_main_getopt_capture_arguments);
  return UNITY_END();
}
