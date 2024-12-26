//go:build ignore

#include <linux/types.h>

#define MAX_DOMAIN_LEN 256

#define QTYPE_A     1
#define QTYPE_CNAME 5
#define QTYPE_AAAA  28
#define QTYPE_MX    15
#define QTYPE_NS    2

#define QCLASS_IN   1


// https://www.rfc-editor.org/rfc/rfc1035.html

/*
Header section format
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

*/

struct dns_flags {
  __u8 qr : 1;
  __u8 opcode : 4;
  __u8 aa : 1;
  __u8 tc : 1;
  __u8 rd : 1;
  __u8 ra : 1;
  __u8 z : 3;
  __u8 rcode : 4;
} __attribute__((packed));

struct dns_header {
  __u16 id;
  struct dns_flags flags;
  __u16 qdcount;
  __u16 ancount;
  __u16 nscount;
  __u16 arcount;
} __attribute__((packed));

/*
Question section format
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

struct dns_question {
  char qname[256];
  __u16 qtype;
  __u16 qclass;
} __attribute__((packed));
