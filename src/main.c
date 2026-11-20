#include "report.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef TEST
#define main main_exclude
#endif

/** Read one capture file and delegate all parsing/reporting to the report layer. */
int main(int argc, char **argv)
{
    /* main performs command-line and file I/O only; decoding remains in report.h. */
    opterr = 0;
    int summary_only = 0;
    int option;
    while ((option = getopt(argc, argv, "s")) != -1) {
        if (option == 's') {
            summary_only = 1;
        } else {
            fprintf(stderr,
                    "Usage: myapp [-s] <capture>\n"
                    "\n"
                    "  -s         print only the flow summary\n"
                    "  <capture>  a pcap file of Ethernet frames\n");
            return 1;
        }
    }
    if (optind != argc - 1) {
        fprintf(stderr,
                "Usage: myapp [-s] <capture>\n"
                "\n"
                "  -s         print only the flow summary\n"
                "  <capture>  a pcap file of Ethernet frames\n");
        return 1;
    }
    const char *capture_path = argv[optind];
    FILE *file = fopen(capture_path, "rb");
    if (file == NULL) {
        fprintf(stderr, "cannot open %s\n", capture_path);
        return 1;
    }
    /* Determine file size before one allocation and one read. */
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        fprintf(stderr, "cannot read %s\n", capture_path);
        return 1;
    }
    /* ftell supplies the byte count for the caller-owned in-memory capture. */
    long length = ftell(file);
    if (length < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        fprintf(stderr, "cannot read %s\n", capture_path);
        return 1;
    }
    uint8_t *bytes = malloc(length > 0 ? (size_t)length : 1);
    if (bytes == NULL) {
        fclose(file);
        fprintf(stderr, "out of memory\n");
        return 1;
    }
    size_t got = fread(bytes, 1, (size_t)length, file);
    fclose(file);
    if (got != (size_t)length) {
        free(bytes);
        fprintf(stderr, "cannot read %s\n", capture_path);
        return 1;
    }
    int result = summary_only
        ? report_capture_bytes_summary(bytes, got, stdout)
        : report_capture_bytes(bytes, got, stdout);
    free(bytes);
    if (result != 0) {
        fprintf(stderr, "%s is not a supported Ethernet pcap file\n", capture_path);
        return 1;
    }
    return 0;
}