#include "rfc_structs.h"

void printHeader(struct Header const * const h)
{
    static const char opCodeNames[16][16] =
    {"QUERY",
     "IQUERY",
     "STATUS"};

    static const char responseCodeNames[16][16] =
    {"NO_ERROR",
     "FORMAT_ERROR",
     "SERVER_FAILURE",
     "NAME_ERROR",
     "NOT_IMPLEMENTED",
     "REFUSED"};

    printf("id: %u\n",
           h->id);
    printf("isResponse: %s\n",
           h->isResponse ? "true" : "false");
    printf("opCode: %s\n",
           opCodeNames[h->opCode]);
    printf("isAuthoritativeAnswer: %s\n",
           h->isAuthoritativeAnswer ? "true" : "false");
    printf("isTruncated: %s\n",
           h->isTruncated ? "true" : "false");
    printf("isRecursionDesired: %s\n",
           h->isRecursionDesired ? "true" : "false");
    printf("isRecursionAvailable: %s\n",
           h->isRecursionAvailable ? "true" : "false");
    printf("z: %d\n",
           h->z);
    printf("responseCode: %s\n",
           responseCodeNames[h->responseCode]);
    printf("questionSectionCount: %u\n",
           h->questionsCount);
    printf("answerSectionCount: %u\n",
           h->answersCount);
    printf("nameServerSectionCount: %u\n",
           h->authorityCount);
    printf("additionalSectionCount: %u\n",
           h->additionalCount);
}

void printQuestion(struct Question const * const q)
{
    printf("Domain name: %s\n", q->domainName);
    puts("Type of resource record:");
    switch (q->typeOfRR) {
    case RR_TYPE_A:
        puts("A - a host address");
        break;
    case RR_TYPE_NS:
        puts("NS - an authoritative name server");
        break;
    case RR_TYPE_MD:
        puts("MD - a mail destination (obsolete)");
        break;
    case RR_TYPE_MF:
        puts("MF - a mail forwarder (obsolete)");
        break;
    case RR_TYPE_CNAME:
        puts("CNAME - the canonical name for an alias");
        break;
    case RR_TYPE_SOA:
        puts("SOA - marks the start of a zone of authority");
        break;
    case RR_TYPE_MB:
        puts("MB - a mailbox domain name (EXPERIMENTAL)");
        break;
    case RR_TYPE_MG:
        puts("MG - a mail group member (EXPERIMENTAL)");
        break;
    case RR_TYPE_MR:
        puts("MR - a mail rename domain name (EXPERIMENTAL)");
        break;
    case RR_TYPE_NULL:
        puts("NULL - a null RR (EXPERIMENTAL)");
        break;
    case RR_TYPE_WKS:
        puts("WKS - a well known service description");
        break;
    case RR_TYPE_PTR:
        puts("PTR - a domain name pointer");
        break;
    case RR_TYPE_HINFO:
        puts("HINFO - host information");
        break;
    case RR_TYPE_MINFO:
        puts("MINFO - mailbox or mail list information");
        break;
    case RR_TYPE_MX:
        puts("MX - mail exchange");
        break;
    case RR_TYPE_TXT:
        puts("TXT - text strings");
        break;
    case RR_TYPE_AXFR:
        puts("AXFR - a request for a transfer of an entire zone");
        break;
    case RR_TYPE_MAILB:
        puts("MAILB - a request for mailbox-related records (MB, MG or MR)");
        break;
    case RR_TYPE_MAILA:
        puts("MAILA - a request for mail agent RRs (obsolete)");
        break;
    case RR_TYPE_ALL:
        puts("* - a request for all records");
        break;
    default:
        puts("Unknown request type");
    }
    puts("Class of resource record:");
    switch (q->classOfRR) {
    case RR_CLASS_IN:
        puts("IN - the Internet");
        break;
    case RR_CLASS_CS:
        puts("CS - the CSNET class (obsolete)");
        break;
    case RR_CLASS_CH:
        puts("CH - the CHAOS class");
        break;
    case RR_CLASS_HS:
        puts("HS - Hesiod");
        break;
    case RR_CLASS_ALL:
        puts("* - any class");
        break;
    default:
        puts("Unknown class");
    }
}

void printResourceRecord(struct ResourceRecord const * const r)
{
    struct in_addr host;
    host.s_addr = r->host;

    printQuestion((struct Question *) r);
    printf("TTL: %d\n", r->ttl);
    printf("Length of data: %d\n", r->lengthOfRData);
    if (r->typeOfRR == RR_TYPE_A)
        printf("RDATA IP: %s\n", inet_ntoa(host));
}
