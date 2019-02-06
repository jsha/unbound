#include "config.h"
#include "util/regional.h"
#include "util/fptr_wlist.h"
#include "sldns/sbuffer.h"

#define SZ 10000

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	sldns_buffer *pkt = sldns_buffer_new(len);
	sldns_buffer_init_frm_data(pkt, (void*)buf, len);

	struct regional *region = regional_create();

	struct msg_parse* prs;
	struct edns_data edns;
	prs = (struct msg_parse*)malloc(sizeof(struct msg_parse));
	if(!prs) {
		printf("out of memory on incoming message\n");
		return 1;
	}
	memset(prs, 0, sizeof(*prs));
	memset(&edns, 0, sizeof(edns));
	sldns_buffer_set_position(pkt, 0);
	if(parse_packet(pkt, prs, region) != LDNS_RCODE_NOERROR) {
		printf("parse error\n");
		return 1;
	}
}

#define BUF_SIZE 65536
int main(int argc, char** argv)
{
    LLVMFuzzerInitialize(&argc, &argv);

    while (__AFL_LOOP(10000)) {
        uint8_t *buf = malloc(BUF_SIZE);
        size_t size = read(0, buf, BUF_SIZE);

        LLVMFuzzerTestOneInput(buf, size);
        free(buf);
    }

    return 0;
}

