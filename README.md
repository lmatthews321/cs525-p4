# Project P4 Packet Capture and Analysis

- Name: Lael Matthews
- Email: laelmatthews@u.boisestate.edu
- Class: CS525

## Known Bugs or Issues

No known bugs or issues are present. Only one small section is excluded from the coverage report: a defensive unexpected-status branch in `src/lab.c`. A valid, initialized pcap reader can only return PCAP_OK, PCAP_END, or PCAP_TRUNCATED, so this branch is unreachable during normal operation. The test may not even be necessary, but I left it in anyway.

## Experience

Creating the code for this project was quick with Copilot CLI, and I did not encounter many mistakes. Some formatting issues, such as using "A" for ACK instead of ".", omitting "[ ]", and failing to specify ARP requests and replies in the descriptions, were quickly corrected. Wireshark's output matched my results, with a couple of exceptions explained in the analysis. My biggest concern was accidentally letting Copilot implement a parsing method or perform another action prohibited by the project guidelines. The code seems compliant after I reviewed it against those guidelines.

When cross-checking the results against Wireshark, the Conversations window matched my flow summary, although the conversations were not in the same order. There were some discrepancies when comparing the snaplen and malformed pcaps, which are explained further in the analysis section. It was nice to learn how to display checksums and turn off relative sequence numbers. I used the raw sequence numbers when comparing results, and they matched. In `snaplen.pcap`, Wireshark specifically states, "Packet size limited during capture," making it clear that the full packet was not captured.

I did try running a capture myself using tcpdump and it returned 62 frames with a summary of 6 conversations. I did notice the cksum=bad but also some cksum=ok. The ok values were on the packets received which makes sense because they don't fall under the packets sent scenario where the network card computes the checksum after the capture has already copied the segment. This is a similar artifact to the 42 vs 60 byte ARP question. It's not surprising that there were 6 conversations when only one was to example.com. I think the other conversations were background services that the codespaces VM was using. 

## Design

The project has three layers: reading capture records, parsing network protocols, and reporting decoded frames and flow statistics.

The `pcap.h` layer reads records from a capture stored in a memory buffer; it does not parse network protocols or read files. It validates the pcap global header and checks that each record header and packet body fit within the available data. Its status values indicate success, the end of the capture, truncated data, or invalid input. Each record provides a packet’s timestamp, lengths, and packet data for the next layer.

The `headers.h` layer defines structures and parsing functions for Ethernet, ARP, IPv4, TCP, and UDP headers. Each parser receives a pointer and a length, then either fills in the corresponding structure or returns a status indicating success, truncated data, or invalid data. The layer also provides checksum and formatting helpers for MAC addresses, IPv4 addresses, and TCP flags.

The `report.h` layer uses the pcap reader and protocol parsers to decode frames and produce formatted frame output. Each frame report contains information such as the frame number, timestamp, and a description of the decoded packet. Separately, a flow table aggregates packet and byte counts by flow and is used to produce the summary.

The main function handles command-line options and reads the capture file into memory. It then calls the reporting functions, which write the frame output and/or flow summary to the supplied output stream, usually the terminal.

## Analysis - Wireshark

| Capture | Flow | Your packets | Your bytes | Wireshark packets | Wireshark bytes |
|---|---|---:|---:|---:|---:|
|day-in-the-life|UDP 0.0.0.0:68 <> 255.255.255.255:67|2|684|2|684|
|day-in-the-life|UDP 68.85.2.1:67 <> 255.255.255.255:68|2|684|2|684|
|day-in-the-life|UDP 68.85.2.101:51334 <> 68.87.71.226:53|2|164|2|164|
|day-in-the-life|TCP 64.233.169.105:80 <> 68.85.2.101:49152|13|4403|13|4403|
|day-in-the-life|UDP 64.233.169.105:33434 <> 68.85.2.101:41337|1|82|1|82|
|day-in_the-life-be|UDP 0.0.0.0:68 <> 255.255.255.255:67|2|684|2|684|
|day-in-the-life-be|UDP 68.85.2.1:67 <> 255.255.255.255:68|2|684|2|684|
|day-in-the-life-be|UDP 68.85.2.101:51334 <> 68.87.71.226:53|2|164|2|164|
|day-in-the-life-be|TCP 64.233.169.105:80 <> 68.85.2.101:49152|13|4403|13|4403|
|day-in-the-life-be|UDP 64.233.169.105:33434 <> 68.85.2.101:41337|1|82|1|82|
|snaplen|UDP 0.0.0.0:68 <> 255.255.255.255:67|2|192|2|684|
|snaplen|UDP 68.85.2.1:67 <> 255.255.255.255:68|2|192|2|684|
|snaplen|UDP 68.85.2.101:51334 <> 68.87.71.226:53|2|164|2|164|
|snaplen|TCP 64.233.169.105:80 <> 68.85.2.101:49152|13|918|13|4403|
|snaplen|UDP 64.233.169.105:33434 <> 68.85.2.101:41337|1|82|1|82|
|truncated|UDP 0.0.0.0:68 <> 255.255.255.255:67|2|684|2|684|
|truncated|UDP 68.85.2.1:67 <> 255.255.255.255:68|2|684|2|684|
|truncated|UDP 68.85.2.101:51334 <> 68.87.71.226:53|2|164|2|164|
|truncated|TCP 64.233.169.105:80 <> 68.85.2.101:49152|3|186|3|186|
|malformed|UDP 10.0.0.1:5000 <> 10.0.0.2:6000|1|47|4|188|
|malformed|TCP 10.0.0.1:5000 <> 10.0.0.2:80|1|54|2|108|

Five flows differ between myapp and Wireshark. The first three are from `snaplen.pcap`. The UDP flows `0.0.0.0:68 <> 255.255.255.255:67` and `68.85.2.1:67 <> 255.255.255.255:68`, and the TCP flow `64.233.169.105:80 <> 68.85.2.101:49152`, differ because of how Wireshark calculates bytes in its Conversations window. It reports bytes on the wire rather than captured bytes, which is what we want to compare here. There are two ways to find the actual captured-byte totals. One is to right-click the conversation, select "Apply as Filter," and count the captured bytes in the filtered packet view. Alternatively, tshark can sum them automatically. The following command was used for the TCP flow and produced the same byte count as myapp.

tshark -r snaplen.pcap -Y "ip.addr==68.85.2.101 && ip.addr==64.233.169.105 && tcp.dstport==49152 || tcp.dstport==80" -T fields -e frame.cap_len | awk '{s+=$1} END {print s}'

The other two conflicting results are from the malformed-data flows. These differ because myapp specifically rejects malformed packets and counts only the packet that was formatted correctly. The output matches `malformed.txt`. Wireshark is more permissive and still counts malformed packets, so it counts all four packets in the UDP flow and both packets in the TCP flow that were transmitted.

#### Why do the first DHCP messages come from 0.0.0.0 and go to 255.255.255.255?
The first DHCP messages come from 0.0.0.0 because the device has not yet been assigned an IP address and is requesting one using 0.0.0.0 as its source address. It does not know where the DHCP server is, either, so it has to broadcast the request on the local network using 255.255.255.255.

#### The ARP request is 42 bytes and the reply is 60. Why?
The actual ARP request is only 42 bytes: 14 bytes for the Ethernet header and 28 bytes for the payload. When the request is sent, it is captured at this size before extra padding and the FCS are added. The minimum Ethernet frame size is 64 bytes, so the device that owns the requested IP address sends a 64-byte reply containing its MAC address (14-byte header, 28-byte payload, 18 bytes of padding, and a 4-byte FCS). The FCS is a CRC check that the network interface card (NIC) strips off, so the captured reply is 64 - 4 = 60 bytes.

#### Which frame has a bad checksum, and what did TCP do about it? Name the frames.
Frame 15 has the bad checksum, so TCP dropped the packet. After receiving additional data in frame 16, the receiver does not acknowledge the new data in frame 17 and continues to acknowledge sequence number 2215467234, which was expected after frame 15. The sender then retransmits the data in frame 18, and the receiver acknowledges it in frame 19.

#### What is frame 24, and what made the router send it?
Frame 24 is an ICMP Time to Live Exceeded message. The router sent it because the previous frame had a TTL of 1, so it expired at the first router.
