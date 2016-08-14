#include "rfc_structs.h"
#include "log.h"

static char logString[MAX_DOMAIN_LENGTH];

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

    sprintf(logString, "id: %u\n",
           h->id);
    logMessage(logString);

    sprintf(logString, "isResponse: %s\n",
           h->isResponse ? "true" : "false");
    logMessage(logString);

    sprintf(logString, "opCode: %s\n",
           opCodeNames[h->opCode]);
    logMessage(logString);

    sprintf(logString, "isAuthoritativeAnswer: %s\n",
           h->isAuthoritativeAnswer ? "true" : "false");
    logMessage(logString);

    sprintf(logString, "isTruncated: %s\n",
           h->isTruncated ? "true" : "false");
    logMessage(logString);

    sprintf(logString, "isRecursionDesired: %s\n",
           h->isRecursionDesired ? "true" : "false");
    logMessage(logString);

    sprintf(logString, "isRecursionAvailable: %s\n",
           h->isRecursionAvailable ? "true" : "false");
    logMessage(logString);

    sprintf(logString, "z: %d\n",
           h->z);
    logMessage(logString);

    sprintf(logString, "responseCode: %s\n",
           responseCodeNames[h->responseCode]);
    logMessage(logString);

    sprintf(logString, "questionSectionCount: %u\n",
           h->questionsCount);
    logMessage(logString);

    sprintf(logString, "answerSectionCount: %u\n",
           h->answersCount);
    logMessage(logString);

    sprintf(logString, "nameServerSectionCount: %u\n",
           h->authorityCount);
    logMessage(logString);

    sprintf(logString, "additionalSectionCount: %u\n",
           h->additionalCount);
    logMessage(logString);
}

void printQuestion(struct Question const * const q)
{
    sprintf(logString, "Domain name: %s\n", q->domainName);
    logMessage(logString);

    logMessage("Type of resource record:");
    switch (q->typeOfRR) {
    case RR_TYPE_A:
        logMessage("A - a host address");
        break;
    case RR_TYPE_NS:
        logMessage("NS - an authoritative name server");
        break;
    case RR_TYPE_MD:
        logMessage("MD - a mail destination (obsolete)");
        break;
    case RR_TYPE_MF:
        logMessage("MF - a mail forwarder (obsolete)");
        break;
    case RR_TYPE_CNAME:
        logMessage("CNAME - the canonical name for an alias");
        break;
    case RR_TYPE_SOA:
        logMessage("SOA - marks the start of a zone of authority");
        break;
    case RR_TYPE_MB:
        logMessage("MB - a mailbox domain name (EXPERIMENTAL)");
        break;
    case RR_TYPE_MG:
        logMessage("MG - a mail group member (EXPERIMENTAL)");
        break;
    case RR_TYPE_MR:
        logMessage("MR - a mail rename domain name (EXPERIMENTAL)");
        break;
    case RR_TYPE_NULL:
        logMessage("NULL - a null RR (EXPERIMENTAL)");
        break;
    case RR_TYPE_WKS:
        logMessage("WKS - a well known service description");
        break;
    case RR_TYPE_PTR:
        logMessage("PTR - a domain name pointer");
        break;
    case RR_TYPE_HINFO:
        logMessage("HINFO - host information");
        break;
    case RR_TYPE_MINFO:
        logMessage("MINFO - mailbox or mail list information");
        break;
    case RR_TYPE_MX:
        logMessage("MX - mail exchange");
        break;
    case RR_TYPE_TXT:
        logMessage("TXT - text strings");
        break;
    case RR_TYPE_AXFR:
        logMessage("AXFR - a request for a transfer of an entire zone");
        break;
    case RR_TYPE_MAILB:
        logMessage("MAILB - a request for mailbox-related records (MB, MG or MR)");
        break;
    case RR_TYPE_MAILA:
        logMessage("MAILA - a request for mail agent RRs (obsolete)");
        break;
    case RR_TYPE_ALL:
        logMessage("* - a request for all records");
        break;
    default:
        logMessage("Unknown request type");
    }

    logMessage("Class of resource record:");
    switch (q->classOfRR) {
    case RR_CLASS_IN:
        logMessage("IN - the Internet");
        break;
    case RR_CLASS_CS:
        logMessage("CS - the CSNET class (obsolete)");
        break;
    case RR_CLASS_CH:
        logMessage("CH - the CHAOS class");
        break;
    case RR_CLASS_HS:
        logMessage("HS - Hesiod");
        break;
    case RR_CLASS_ALL:
        logMessage("* - any class");
        break;
    default:
        logMessage("Unknown class");
    }
}

void printResourceRecord(struct ResourceRecord const * const r)
{
    struct in_addr host;
    host.s_addr = r->host;

    printQuestion((struct Question *) r);
    sprintf(logString, "TTL: %d\n", r->ttl);
    logMessage(logString);

    sprintf(logString, "Length of data: %d\n", r->lengthOfRData);
    logMessage(logString);

    if (r->typeOfRR == RR_TYPE_A) {
        sprintf(logString, "RDATA IP: %s\n", inet_ntoa(host));
        logMessage(logString);
    }
}
