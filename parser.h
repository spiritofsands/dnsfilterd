#ifndef PARSER_H
#define PARSER_H

#include <stdlib.h>
#include <ctype.h>

#include "rfc_structs.h"
#include "blacklist_loader.h"
#include "printAndExit.h"

typedef unsigned char u_char;
typedef unsigned int u_int;

struct DNSpacket
{
    struct Header header;
    struct Question *questionsArray;
    struct ResourceRecord *answersArray,
            *authorityArray,
            *additionalArray;
};
void destroyDNSpacket(struct DNSpacket *p);

void createPacketWithCustomHost(u_char buffer[],
                                u_int *bufferLength,
                                struct DNSpacket const *p,
                                uint32_t ultimateHost);
void writeDomainName(u_char *buffer,
                     u_int32_t *bufferIndex,
                     char const *domainName);

u_int charsBeforeDot(char const *str, u_int pos);

void checkIfBlacklisted(u_char *, u_int *receivedSize,
                          struct Blacklist *const blacklist);
void readQuestion(struct Question * const q,
                  u_char const data[],
                  u_int * const index);
void readResourceRecord(struct ResourceRecord * const r,
                        u_char const data[],
                        u_int * const index);
void readDomainName(u_char const data[],
                   u_int * const index,
                   char domainName[]);
bool domainIsBlacklisted(char *domain,
                         struct Blacklist const *blacklist);
bool hostIsBlacklisted(uint32_t host,
                  struct Blacklist const *blacklist);

#endif // PARSER_H
