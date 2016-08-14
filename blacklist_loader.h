#ifndef BLACKLIST_LOADER_H
#define BLACKLIST_LOADER_H

#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>

#include "rfc_structs.h"
#include "printAndExit.h"

struct Blacklist
{
    u_long hostsNumber;
    u_long domainsNumber;
    uint32_t *hosts;
    char *domains[MAX_DOMAIN_LENGTH];
    uint32_t ultimateHost;
};

void readBlacklist(char *fileName, struct Blacklist *b);
void freeBlacklistMemory(struct Blacklist *b);

#endif // BLACKLIST_LOADER_H
