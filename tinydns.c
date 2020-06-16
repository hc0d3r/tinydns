#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <poll.h>

#include "tinydns.h"

const char * const tinydns_version = "tinydns v0.1.0";

static void tinydns_init_header(struct tinydns_packet *header, int query_type)
{
	header->id = getpid();

	header->qr = 0;
	header->opcode = htons(query_type);
	header->aa = 0;
	header->tc = 0;
	header->rd = 1;

	header->ra = 0;
	header->z = 0;
	header->rcode = 0;

	header->qdcount = 0;
	header->ancount = 0;
	header->nscount = 0;
	header->arcount = 0;
}

struct tinydns_query *tinydns_init(struct tinydns_query *dns, int query_type)
{
	if (dns == NULL) {
		dns = malloc(sizeof(struct tinydns_query));
		if (dns == NULL)
			goto end;
	}

	memset(dns, 0x0, sizeof(struct tinydns_query));
	tinydns_init_header((struct tinydns_packet *) dns->query, query_type);

	dns->iter = dns->qindex = sizeof(struct tinydns_packet);

	// miliseconds
	dns->timeout = 4000;
	dns->retry = 2;
	dns->port = 53;

end:
	return dns;
}

int tinydns_set_option(struct tinydns_query *dns, int opt, ...)
{
	int status = 0;
	va_list ap;
	char *tmp;

	va_start(ap, opt);

	switch (opt) {
		case DNS_OPT_TIMEOUT:
			dns->timeout = va_arg(ap, int);
			break;

		case DNS_OPT_RETRY:
			dns->retry = va_arg(ap, int);
			break;

		case DNS_OPT_IPV4:
			tmp = va_arg(ap, char *);
			if (inet_pton(AF_INET, tmp, &(dns->address.s4.sin_addr))) {
				dns->address.s4.sin_family = AF_INET;
			} else {
				dns->address.s4.sin_family = 0;
				status = 1;
			}
			break;

		case DNS_OPT_IPV6:
			tmp = va_arg(ap, char *);
			if (inet_pton(AF_INET6, tmp, &(dns->address.s6.sin6_addr))) {
				dns->address.s6.sin6_family = AF_INET6;
			} else {
				dns->address.s6.sin6_family = 0;
				status = 1;
			}
			break;

		case DNS_OPT_PORT:
			dns->port = va_arg(ap, unsigned int);
			if (dns->port == 0)
				status = 1;
			break;

		case DNS_OPT_BUF:
			dns->response = va_arg(ap, void *);
			break;

		case DNS_OPT_BUFSIZE:
			dns->bufsize = va_arg(ap, size_t);
			if (dns->bufsize < 512)
				status = 1;
			break;

		default:
			status = 1;
	}

	va_end(ap);

	return status;
}

int tinydns_add_question(struct tinydns_query *dns, const char *domain, uint16_t qtype)
{
	int lbsize, index = dns->qindex, status = 1;
	uint16_t *qdcount;

	// max ASCII DNS name
	if (strlen(domain) > 253)
		goto end;

	char *next, *prev = (char *)domain;

	while (1) {
		next = strchr(prev, '.');
		if (next == NULL)
			lbsize = strlen(prev);
		else
			lbsize = next - prev;

		if (lbsize == 0) {
			// empty label
			if (next && next[-1] == '.')
				goto end;
			// empty domain or a dot at the end of the domain
			else
				break;
		}

		// check bounds
		if ((index + 1 + lbsize) >= (int)sizeof(dns->query))
			goto end;

		dns->query[index++] = lbsize;
		memcpy(dns->query + index, prev, lbsize);
		index += lbsize;

		if (next == NULL || *(next + 1) == 0)
			break;

		prev = next + 1;
	}

	// check if we have space to QTYPE and QCLASS_IN
	if ((index + 4) >= (int)sizeof(dns->query))
		goto end;

	dns->query[index] = 0x0;
	dns->qindex = index + 5;


	*(uint16_t *)(dns->query + index + 1) = htons(qtype);

	// QCLASS_IN = 1
	*(uint16_t *)(dns->query + index + 3) = htons(1);

	qdcount = &(((struct tinydns_packet *) dns->query)->qdcount);
	*qdcount = htons(ntohs(*qdcount) + 1);

	status = 0;

end:
	return status;
}

int tinydns_send_query(struct tinydns_query *dns)
{
	struct sockaddr *addr;
	struct pollfd pfd;

	int sockfd, family, try, status = 1;
	socklen_t addrlen;

	// assumpts that sin_family and sin6_family are in the same offset
	family = dns->address.s4.sin_family;
	try = dns->retry;

	switch (family) {
		case AF_INET:
			addrlen = sizeof(struct sockaddr_in);
			dns->address.s4.sin_port = htons(dns->port);
			break;
		case AF_INET6:
			addrlen = sizeof(struct sockaddr_in6);
			dns->address.s6.sin6_port = htons(dns->port);
		default:
			goto end;
	}

	sockfd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	if (sockfd == -1)
		goto end;

	pfd.fd = sockfd;
	pfd.events = POLLIN;

	addr = (struct sockaddr *) &(dns->address);

	do {
		if (sendto(sockfd, dns, dns->qindex, 0, addr, addrlen) == -1)
			continue;

		if (poll(&pfd, 1, dns->timeout) == 0)
			continue;

		dns->respsize = recvfrom(sockfd, dns->response, dns->bufsize, 0, addr, &addrlen);

		if (dns->respsize != -1) {
			status = 0;
			break;
		}
	} while (try--);

	if (dns->respsize >= (ssize_t)sizeof(struct tinydns_packet)) {
		struct tinydns_packet *hdr = dns->response;

		hdr->qdcount = ntohs(hdr->qdcount);
		hdr->ancount = ntohs(hdr->ancount);
		hdr->nscount = ntohs(hdr->nscount);
		hdr->arcount = ntohs(hdr->arcount);
		hdr->rcode = ntohs(hdr->rcode);
		hdr->opcode = ntohs(hdr->opcode);
	}

	close(sockfd);

end:
	return status;
}

struct tinydns_packet *tinydns_response_packet(struct tinydns_query *dns)
{
	struct tinydns_packet *hdr;

	if (dns->respsize >= (ssize_t)sizeof(struct tinydns_packet))
		hdr = dns->response;
	else
		hdr = NULL;

	return hdr;
}

static int tinydns_next_question(struct tinydns_rr *rr, struct tinydns_query *dns)
{
	unsigned char *domain, len;
	int status = 0;

	//  1 byte: an empty label: 00
	// 2 bytes: type
	// 2 bytes: class
	if (dns->respsize < (dns->iter + 5))
		goto end;

	domain = (unsigned char *) dns->response;
	rr->name = domain + dns->iter;

	// iterate until finding the empty label
	while ((len = domain[dns->iter])) {
		if (len == 0xc0) {
			dns->iter++;

			if (dns->respsize <= (dns->iter + 4))
				goto end;

			break;
		}

		dns->iter += len + 1;

		if (dns->respsize <= (dns->iter + 4))
			goto end;
	}

	// skip the empty label
	dns->iter++;

	rr->type = ntohs(*(uint16_t *)(domain + dns->iter));
	rr->class = ntohs(*(uint16_t *)(domain + dns->iter + 2));
	rr->ttl = 0;
	rr->rdlength = 0;
	rr->rdata = NULL;

	dns->iter += 4;
	dns->qcount++;
	status = 1;

end:
	return status;
}

int tinydns_next_rr(struct tinydns_rr *rr, struct tinydns_query *dns)
{
	unsigned char *domain, len;
	int status = 0;

	if (dns->qcount < dns->response->qdcount) {
		status = tinydns_next_question(rr, dns);
		goto end;
	}

	//  1 byte: an empty label: 00
	// 2 bytes: type
	// 2 bytes: class
	// 4 bytes: ttl
	// 2 bytes: rdlength
	if (dns->respsize < (dns->iter + 11))
		goto end;

	domain = (unsigned char *) dns->response;
	rr->name = domain + dns->iter;

	// iterate until finding the empty label
	while ((len = domain[dns->iter])) {
		// domain name compression
		if (len == 0xc0) {
			dns->iter++;

			if (dns->respsize <= (dns->iter + 10))
				goto end;

			break;
		}

		dns->iter += len + 1;

		if (dns->respsize <= (dns->iter + 10))
			goto end;
	}

	// skip the empty label or ptr byte used in domain compression
	dns->iter++;

	rr->rdlength = ntohs(*(uint16_t *)(domain + dns->iter + 8));

	// check bounds, change rdlength if it exceeds the response size
	if ((rr->rdlength + dns->iter + 10) > dns->respsize)
		rr->rdlength = dns->respsize - (dns->iter + 10);

	rr->type = ntohs(*(uint16_t *)(domain + dns->iter));
	rr->class = ntohs(*(uint16_t *)(domain + dns->iter + 2));
	rr->ttl = ntohl(*(uint32_t *)(domain + dns->iter + 4));
	rr->rdata = domain + dns->iter + 10;

	dns->iter += rr->rdlength + 10;
	status = 1;

end:
	return status;
}

// this function does not validate the domain name properly
// only extract it if it does not exceed 253 chars
char *tinydns_extract_domain(struct tinydns_query *query, unsigned char *domain)
{
	char buf[256], *strdomain = NULL;
	unsigned char len;

	int pos = 0;

	int offset = domain - (unsigned char *)query->response;
	if (offset >= (int)query->respsize || offset < 0)
		goto end;

	domain = (unsigned char *)query->response;

	while ((len = domain[offset])) {
		if (len == 0xc0) {
			if ((int)query->respsize <= (offset + 1))
				goto end;

			offset = domain[offset + 1];
			if ((int)query->respsize <= offset)
				goto end;

			// prevent an infinite loop
			if (domain[offset] == 0xc0)
				goto end;

			continue;
		}


		if ((int)query->respsize <= (offset + len + 1))
			goto end;

		if ((pos + len + 1) >= 255)
			goto end;

		memcpy(buf + pos, domain + offset + 1, len);

		offset += len + 1;
		pos += len;

		buf[pos++] = '.';
	}

	buf[pos] = 0x0;
	strdomain = strdup(buf);

end:
	return strdomain;
}
