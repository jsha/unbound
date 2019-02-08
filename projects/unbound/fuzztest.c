#include "config.h"
#include "util/regional.h"
#include "util/fptr_wlist.h"
#include "sldns/sbuffer.h"

struct regional *region;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	region = regional_create();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	sldns_buffer pktbuf;
	sldns_buffer_init_frm_data(&pktbuf, (void*)buf, len);

	struct msg_parse prs;
	struct edns_data edns;
	memset(&prs, 0, sizeof(prs));
	memset(&edns, 0, sizeof(edns));
	if(parse_packet(&pktbuf, &prs, region) != LDNS_RCODE_NOERROR) {
		// do nothing
	}
	return 0;
}
