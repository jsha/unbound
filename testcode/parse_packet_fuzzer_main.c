/*
 * parse_packet_fuzzer_main.c - parse a packet provided on stdin (for fuzzing).
 *
 */
#include "config.h"
#include "util/regional.h"
#include "util/fptr_wlist.h"
#include "sldns/sbuffer.h"

#define SZ 10000

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len);

int main() {
	char buffer[SZ];
	size_t n_read = fread(buffer, 1, SZ, stdin);
	if (n_read == SZ) {
		printf("input too big\n");
		return 1;
	}

	LLVMFuzzerTestOneInput(buffer, n_read);
}
