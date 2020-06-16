tinydns
=======

A tiny library to perform DNS queries based on RFC 1035,
works only with UDP servers.

Usage example
-------------

```c
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <tinydns.h>

int main(int argc, char **argv)
{
	struct tinydns_packet *response;
	struct tinydns_query dns;
	struct tinydns_rr rrbuf;

	char buf[30000], ip[16];

	int status = 1;
	uint16_t i;

	if (argc != 2) {
		printf("%s [domain]\n", argv[0]);
		goto end;
	}

	tinydns_init(&dns, QUERY_STANDARD);

	// timeout in miliseconds
	tinydns_set_option(&dns, DNS_OPT_TIMEOUT, 3000);

	// number of times to retry if timeout exceeds
	tinydns_set_option(&dns, DNS_OPT_RETRY, 2);

	// DNS server ipv4
	tinydns_set_option(&dns, DNS_OPT_IPV4, "8.8.8.8");

	// or you can use ipv6...
	// tinydns_set_option(&dns, DNS_OPT_IPV6, "2001:4860:4860::8888");

	// response buffer, it should be greater than or equal to 512 bytes
	tinydns_set_option(&dns, DNS_OPT_BUF, buf);
	tinydns_set_option(&dns, DNS_OPT_BUFSIZE, sizeof(buf));

	// if the server is on a port other than the default port(53):
	// tinydns_set_option(&dns, DNS_OPT_PORT, custom_port);

	printf("libversion: %s\n\n", tinydns_version);

	if (tinydns_add_question(&dns, argv[1], QTYPE_A)) {
		printf("failed to add a question\n");
		goto end;
	}

	if (tinydns_send_query(&dns)) {
		printf("failed to send dns query...\n");
		goto end;
	}

	response = tinydns_response_packet(&dns);
	if (response == NULL) {
		printf("response is too short...\n");
		goto end;
	}

	printf("-- header --\n");
	printf("id:                         %u\n", response->id);

	printf("query(0) or response(1):    %u\n", response->qr);
	printf("opcode:                     %u\n", response->opcode);
	printf("authoritative answer:       %u\n", response->aa);
	printf("truncated packet:           %u\n", response->tc);
	printf("recursion desired:          %u\n", response->rd);

	printf("recursion available:        %u\n", response->ra);
	printf("zero:                       %u\n", response->z);
	printf("response code (0 is okay):  %u\n", response->rcode);

	printf("questions:                  %u\n", response->qdcount);
	printf("answers:                    %u\n", response->ancount);
	printf("name servers:               %u\n", response->nscount);
	printf("additional records:         %u\n", response->arcount);
	printf("---\n\n");

	printf("RRs (resource records):\n");

	while (tinydns_next_rr(&rrbuf, &dns)) {
		char *domain = tinydns_extract_domain(&dns, rrbuf.name);
		printf("\n\n");
		printf("domain:      %s\n", domain);
		printf("type:        %u\n", rrbuf.type);
		printf("class:       %u\n", rrbuf.class);
		printf("ttl:         %u\n", rrbuf.ttl);
		printf("rdlength:    %u\n", rrbuf.rdlength);

		if (rrbuf.rdlength == 4 && rrbuf.type == QTYPE_A) {
			printf("rdata(ipv4): %s\n", inet_ntop(AF_INET, rrbuf.rdata, ip, sizeof(ip)));
		} else {
			printf("rdata:      ");
			for (i = 0; i < rrbuf.rdlength; i++) {
				printf(" %02x", *((unsigned char *)rrbuf.rdata + i));
			}
			printf("\n");
		}

		free(domain);
	}

	status = 0;

end:
	return status;
}
```

Contributing
------------
You can help with code, or donating money.
If you wanna help with code, use the kernel code style as a reference.

Paypal: [![](https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=RAG26EKAYHQSY&currency_code=BRL&source=url)

BTC: 1PpbrY6j1HNPF7fS2LhG9SF2wtyK98GSwq
