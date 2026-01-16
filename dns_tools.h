#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/*****************************************************************************
 * DNS TOOLS
 *****************************************************************************/
struct dns_msg {
	char    name[64];
	uint8_t len_name;

	uint16_t query_type;
	uint16_t query_class;

	/** Raw (UDP) packet len */
	size_t len_raw;

	/** Offset inside packet (when actively parsing) */
	size_t ofs;

	/** Set to true if something is not right */
	uint32_t malformed;
};

static void dns_msg_init(struct dns_msg *self)
{
	self->len_name = 0u;

	self->query_type  = 0u;
	self->query_class = 0u;

	self->ofs = 0u;

	self->len_raw = 0u;

	self->malformed = false;
}

/** Parses DNS header */
static void dns_msg_parse_hdr(struct dns_msg *self, uint8_t *data)
{
	(void)data;

	if ((self->len_raw < 12u) || (self->ofs != 0u)) {
		/* Can't exceed msg len */
		self->malformed = __LINE__;
	} else {
		self->ofs = 12;
	}
}

/** Parses DNS name list. Appends single entry into aaa.bbb.ccc form string.
 *  Returns true if it's last entry, or if it's malformed.
 *  DNS name list has the following binary format: [len]text[len]text...[0]
 *  	where [len] is a single byte and text is ASCII encoded text */
static bool dns_msg_parse_name_entry(struct dns_msg *self, uint8_t *data)
{
	/* Single list entry length */
	uint8_t  len = data[self->ofs];
	uint16_t len_full = 1u + (uint16_t)len;

	/* Last entry always has zero length */
	bool last_entry = data[len];

	if (((self->ofs + len_full) > self->len_raw) ||
	    ((self->len_name + len + 1u) > 64u)) {
		self->malformed = __LINE__;
	} else {		
		uint8_t i;

		self->ofs += 1u; /* Skip len byte */

		/* Append dot into name */
		if (!last_entry && (self->len_name > 0u)) {
			self->name[self->len_name] = '.';
			self->len_name++;
		}

		/* Appends entry into readable form string */
		for (i = 0; i < len; i++) {
			self->name[self->len_name] = data[self->ofs];

			/* Advance to the next byte */
			self->ofs++;
			self->len_name++;
		}
	}

	/* Insert null terminator at the end of last entry */
	if (last_entry) {
		self->name[self->len_name] = '\0';
	}

	return last_entry || self->malformed;
}

static void dns_msg_parse(struct dns_msg *self, uint8_t *data) {
	/* Parse header */
	dns_msg_parse_hdr(self, data);

	if (self->malformed == 0u) {
		/* Parse all entries */
		while (dns_msg_parse_name_entry(self, data) != true) {};
	}

	if (self->malformed == 0u) {
		/* Parse query type and class */
		if ((self->ofs + 4u) > self->len_raw) {
			self->malformed = __LINE__;
		} else {
			self->query_type  = (data[self->ofs + 0u] << 8) |
					    (data[self->ofs + 1u] << 0);
			self->query_class = (data[self->ofs + 2u] << 8) |
					    (data[self->ofs + 3u] << 0);

			self->ofs += 4u;
		}
	};
}
