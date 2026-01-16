#include "dns_tools.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

void test_dns_parsing_standard(void)
{
	struct dns_msg msg;
	/* DNS Header (12 bytes) + \003www\006google\003com\000 + Type/Class */
	uint8_t mock_pkt[] = {
		0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, /* Header */
		0x03, 'w', 'w', 'w', 
		0x06, 'g', 'o', 'o', 'g', 'l', 'e', 
		0x03, 'c', 'o', 'm', 
		0x00,                   /* Terminator */
		0x00, 0x01, 0x00, 0x01  /* Type A, Class IN */
	};

	dns_msg_init(&msg);
	msg.len_raw = sizeof(mock_pkt);
	
	dns_msg_parse(&msg, mock_pkt);

	if (msg.malformed) {
		printf("Test Failed: Packet marked malformed at line %u\n",
			msg.malformed);
		assert(0);
	} else if (strcmp(msg.name, "www.google.com") != 0) {
		printf("Test Failed: Name mismatch: %s\n", msg.name);
		assert(0);
	} else if (msg.query_type != 1) {
		printf("Test Failed: Type mismatch: %u\n", msg.query_type);
		assert(0);
	} else {
		printf("Test Passed: www.google.com parsed correctly\n");
	}
}

int main(void) {
	test_dns_parsing_standard();

	return 0;
}
