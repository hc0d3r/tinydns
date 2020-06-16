#ifndef __TINYDNS_H__
#define __TINYDNS_H__

#include <stdint.h>
#include <arpa/inet.h>

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ || \
	defined(__BIG_ENDIAN__)
	#define IS_BIG_ENDIAN
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ || \
	defined(__LITTLE_ENDIAN__)
	#define IS_LITTLE_ENDIAN
#else
#error "can't determine the machine's endianness, define __BIG_ENDIAN__ or __LITTLE_ENDIAN__ properly"
#endif

extern const char * const tinydns_version;

// opcode
enum {
	QUERY_STANDARD,
	QUERY_INVERSE,
	QUERY_STATUS
};

// query type
enum {
	QTYPE_A = 1,		// a host address
	QTYPE_NS = 2,		// an authoritative name server
	QTYPE_MD = 3,		// a mail destination (Obsolete - use MX)
	QTYPE_MF = 4,		// a mail forwarder (Obsolete - use MX)
	QTYPE_CNAME = 5,	// the canonical name for an alias
	QTYPE_SOA = 6,		// marks the start of a zone of authority
	QTYPE_MB = 7,		// a mailbox domain name (EXPERIMENTAL)
	QTYPE_MG = 8,		// a mail group member (EXPERIMENTAL)
	QTYPE_MR = 9,		// a mail rename domain name (EXPERIMENTAL)
	QTYPE_NULL = 10,	// a null RR (EXPERIMENTAL)
	QTYPE_WKS = 11,		// a well known service description
	QTYPE_PTR = 12,		// a domain name pointer
	QTYPE_HINFO = 13,	// host information
	QTYPE_MINFO = 14,	// mailbox or mail list information
	QTYPE_MX = 15,		// mail exchange
	QTYPE_TXT = 16,		// text strings
	QTYPE_AAAA = 28,	// ipv6 addr
	QTYPE_ANY = 255
};

// options
enum {
	DNS_OPT_TIMEOUT,
	DNS_OPT_RETRY,
	DNS_OPT_IPV4,
	DNS_OPT_IPV6,
	DNS_OPT_PORT,
	DNS_OPT_BUF,
	DNS_OPT_BUFSIZE
};

// structs

struct tinydns_packet {
	uint16_t id;

#ifdef IS_LITTLE_ENDIAN
	uint8_t rd:1;
	uint8_t tc:1;
	uint8_t aa:1;
	uint8_t opcode:4;
	uint8_t qr:1;

	uint8_t rcode:4;
	uint8_t z:3;
	uint8_t ra:1;
#else
	uint8_t qr:1;
	uint8_t opcode:4;
	uint8_t aa:1;
	uint8_t tc:1;
	uint8_t rd:1;

	uint8_t ra:1;
	uint8_t z:3;
	uint8_t rcode:4;
#endif

	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;

	unsigned char data[];
};

struct tinydns_query {
	unsigned char query[512];

	// DNS_OPT_BUF
	struct tinydns_packet *response;

	// DNS_OPT_IPV[46]
	union {
		struct sockaddr_in s4;
		struct sockaddr_in6 s6;
	} address;

	// RR index
	int iter;

	// DNS_OPT_BUFSIZE
	size_t bufsize;

	// response size
	ssize_t respsize;

	// question index
	int qindex;

	// number of questions
	uint16_t qcount;

	// DNS_OPT_PORT
	uint16_t port;

	// DNS_OPT_TIMEOUT
	int timeout;

	// DNS_OPT_RETRY
	int retry;
};

struct tinydns_rr {
	unsigned char *name;
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlength;
	void *rdata;
};

// functions

struct tinydns_query *tinydns_init(struct tinydns_query *dns, int query_type);
int tinydns_set_option(struct tinydns_query *dns, int opt, ...);
int tinydns_add_question(struct tinydns_query *dns, const char *domain, uint16_t qtype);
int tinydns_send_query(struct tinydns_query *dns);
struct tinydns_packet *tinydns_response_packet(struct tinydns_query *dns);
int tinydns_next_rr(struct tinydns_rr *rr, struct tinydns_query *dns);
char *tinydns_extract_domain(struct tinydns_query *query, unsigned char *domain);

#endif
