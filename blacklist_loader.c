#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>

#include "blacklist_loader.h"

void readBlacklist(char *fileName, struct Blacklist *b)
{
    FILE *fPtr;
    char str[MAX_DOMAIN_LENGTH];
    char *strPtr = str,
            *domainPtr;
    u_int hostCounter, domainCounter, lineCounter;
    u_int maxDomainLengthMinus1 = MAX_DOMAIN_LENGTH-1;
    struct in_addr host;
    u_int i;

    b->domainsNumber = b->hostsNumber = 0;
    b->ultimateHost = 0;

    if ( (fPtr = fopen(fileName, "r")) == NULL )
        printAndExit("Can\'t open blacklist file");

    //count number of hosts and domains
    while ( !feof(fPtr) ) {
        fgets(str, MAX_DOMAIN_LENGTH, fPtr);
        if ( isdigit(str[0]) )
            b->hostsNumber++;
        else if ( isalpha(str[0]) )
            b->domainsNumber++;
    }

    b->hosts = malloc(sizeof(uint32_t) * b->hostsNumber);
    for (i = 0; i < b->domainsNumber; ++i)
        b->domains[i] = malloc(sizeof(char)*MAX_DOMAIN_LENGTH);

    rewind(fPtr);
    hostCounter = domainCounter = lineCounter = 0;
    while ( !feof(fPtr) ) {
        ++lineCounter;

        fgets(str, MAX_DOMAIN_LENGTH, fPtr);
        str[maxDomainLengthMinus1] = '\0';

        if ( isdigit(str[0]) ) {
            if (inet_aton(str, &host) == 0) {//invalid
                printf("Invalid host in blacklist "
                       "(line %u)", lineCounter);
                exit(1);
            }
            b->hosts[hostCounter++] = host.s_addr;
        }
        else if ( isalpha(str[0]) ) {
            domainPtr = b->domains[domainCounter];
            while (*strPtr != '\n' && *strPtr != '\0')
                *(domainPtr++) = *(strPtr++);

            b->domains[domainCounter][maxDomainLengthMinus1] = '\0';

            //if last symbol is not '.' we must add it
            if (*(domainPtr-1) != '.' )
                *(domainPtr ) = '.';
            //it may overwrite \0, but strncmp will deal with it
        }
        else if ( b->ultimateHost == 0 &&
                  str[0] == '=' )
        {
            if (inet_aton(str+1, &host) == 0) {//invalid
                printf("Invalid ultimate host in blacklist "
                       "(line %u)", lineCounter);
                exit(1);
            }
            b->ultimateHost = htonl(host.s_addr);
        }
    }

    fclose(fPtr);

    if (b->ultimateHost == 0) {
        puts("No ultimate host in blacklist "
               "(e.g. =123.123.123.123)");
        exit(1);
    }

    printf("Read %lu hosts and %lu domains\n",
           b->hostsNumber, b->domainsNumber);
}

void freeBlacklistMemory(struct Blacklist *b)
{
    u_int i;
    free(b->hosts);
    for (i = 0; i < b->domainsNumber; ++i)
        free(b->domains[i]);
}
