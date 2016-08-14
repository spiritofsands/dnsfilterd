#include "parser.h"
#include "rfc_structs.h"

void checkIfBlacklisted(u_char *buffer, int *receivedSize,
                           struct Blacklist *const blacklist)
{
    static struct DNSpacket packet;
    static u_char newBuffer[BUFF_SIZE];
    u_int index, bufferIndex, newLength;
    bool isBlacklisted;

    packet.header.id = buffer[0] << 8 | buffer[1];
    packet.header.isResponse = buffer[2] & 0x80;
    packet.header.opCode = (buffer[2] & 0x78) >> 3;
    packet.header.isAuthoritativeAnswer = buffer[2] & 0x04;
    packet.header.isTruncated = buffer[2] & 0x02;
    packet.header.isRecursionDesired = buffer[2] & 0x01;
    packet.header.isRecursionAvailable = buffer[3] & 0x80;
    packet.header.z = (buffer[3] & 0x70) >> 4;
    packet.header.responseCode = buffer[3] & 0x0f;
    packet.header.questionsCount = buffer[4] << 8 | buffer[5];
    packet.header.answersCount = buffer[6] << 8 | buffer[7];
    packet.header.authorityCount = buffer[8] << 8 | buffer[9];
    packet.header.additionalCount = buffer[10] << 8 | buffer[11];

    logMessage("\nHeader:");
    printHeader(&packet.header);

    //question
    bufferIndex = 12;
    //dataPtr = buffer + 12;
    packet.questionsArray = malloc(sizeof(struct Question) *
                            packet.header.questionsCount);
    for (index = 0; index < packet.header.questionsCount; ++index)
    {
        readQuestion(&packet.questionsArray[index],
                     buffer, &bufferIndex);
        logMessage("\nQuestion:\n");
        printQuestion(&packet.questionsArray[index]);
    }

    //answer section
    packet.answersArray = malloc(sizeof(struct ResourceRecord) *
                            packet.header.answersCount);
    for (index = 0; index < packet.header.answersCount; ++index)
    {
        readResourceRecord(&packet.answersArray[index],
                           buffer, &bufferIndex);
        logMessage("\nAnswer:\n");
        printResourceRecord(&packet.answersArray[index]);
    }

    //authority section
    packet.authorityArray = malloc(sizeof(struct ResourceRecord) *
                            packet.header.authorityCount);
    for (index = 0; index < packet.header.authorityCount; ++index)
    {
        readResourceRecord(&packet.authorityArray[index],
                           buffer, &bufferIndex);
        logMessage("\nAuthority #%d:\n");
        printResourceRecord(&packet.authorityArray[index]);
    }

    //additional section
    packet.additionalArray = malloc(sizeof(struct ResourceRecord) *
                            packet.header.additionalCount);
    for (index = 0; index < packet.header.additionalCount; ++index)
    {
        readResourceRecord(&packet.additionalArray[index],
                           buffer, &bufferIndex);
        logMessage("\nadditional:\n");
        printResourceRecord(&packet.additionalArray[index]);
    }

    logMessage("\nSuccessfully parsed");


    //determining if blacklisted
    isBlacklisted = false;
    //look if domain is not blacklisted
    for (index = 0; index < packet.header.questionsCount; ++index)
        if ( domainIsBlacklisted(
                    packet.questionsArray[index].domainName,
                    blacklist) )
        {
            isBlacklisted = true;
            break;
        }

    //look if host is not blacklisted
    if (!isBlacklisted)
        for (index = 0; index < packet.header.answersCount; ++index)
            if ( hostIsBlacklisted(
                        packet.answersArray[index].host,
                        blacklist) )
            {
                isBlacklisted = true;
                break;
            }

    if (!isBlacklisted)
        for (index = 0; index < packet.header.authorityCount; ++index)
            if ( hostIsBlacklisted(
                        packet.authorityArray[index].host,
                        blacklist) )
            {
                isBlacklisted = true;
                break;
            }

    if (!isBlacklisted)
        for (index = 0; index < packet.header.additionalCount; ++index)
            if ( hostIsBlacklisted(
                        packet.additionalArray[index].host,
                        blacklist) )
            {
                isBlacklisted = true;
                break;
            }

    //filtering
    if (isBlacklisted) {
        logMessage("\nFiltered");

        createPacketWithCustomHost(newBuffer, &newLength,
                                   &packet,
                                   blacklist->ultimateHost);
        memcpy(buffer, newBuffer, newLength);
        *receivedSize = newLength;
    }

    destroyDNSpacket(&packet);
}

void createPacketWithCustomHost(u_char buffer[],
                                u_int *bufferLength,
                                struct DNSpacket const *p,
                                uint32_t customHost)
{
    u_int index, bufferIndex,
            answersCount = 1,
            authorityCount = 0,
            additionalCount = 0;

    //header
    buffer[0] = (p->header.id & 0xff00) >> 8;
    buffer[1] = p->header.id & 0x00ff;

    buffer[2] = buffer[3] = 0;
    if(p->header.isResponse)
        buffer[2] |= 0x80;
    buffer[2] |= (p->header.opCode & 0x0f) << 3;
    if(p->header.isAuthoritativeAnswer)
        buffer[2] |= 0x04;
    if(p->header.isTruncated)
        buffer[2] |= 0x02;
    if(p->header.isRecursionDesired)
        buffer[2] |= 0x01;
    if(p->header.isRecursionAvailable)
        buffer[3] |= 0x80;
    buffer[3] |= (p->header.z & 0x07) << 4;
    buffer[3] |= (p->header.responseCode & 0x0f);

    buffer[4] = (p->header.questionsCount & 0xff00) >> 8;
    buffer[5] = (p->header.questionsCount & 0x00ff);
    buffer[6] = (answersCount & 0xff00) >> 8;
    buffer[7] = (answersCount & 0x00ff);
    buffer[8] = (authorityCount & 0xff00) >> 8;
    buffer[9] = (authorityCount & 0x00ff);
    buffer[10] = (additionalCount & 0xff00) >> 8;
    buffer[11] = (additionalCount & 0x00ff);

    //question
    bufferIndex = 12;
    for (index = 0; index < p->header.questionsCount; ++index)
    {
        writeDomainName(buffer, &bufferIndex,
                        p->questionsArray[index].domainName);

        buffer[bufferIndex++] =
                (p->questionsArray[index].typeOfRR & 0xff00) >> 8;
        buffer[bufferIndex++] =
                p->questionsArray[index].typeOfRR & 0x00ff;
        buffer[bufferIndex++] =
                (p->questionsArray[index].classOfRR & 0xff00) >> 8;
        buffer[bufferIndex++] =
                p->questionsArray[index].classOfRR & 0x00ff;
    }

    //one answer
    index = 0;
    //no pointers
    writeDomainName(buffer, &bufferIndex,
                    p->answersArray[index].domainName);

    buffer[bufferIndex++] =
            (p->answersArray[index].typeOfRR & 0xff00) >> 8;
    buffer[bufferIndex++] =
            (p->answersArray[index].typeOfRR & 0x00ff);

    buffer[bufferIndex++] =
            (p->answersArray[index].classOfRR & 0xff00) >> 8;
    buffer[bufferIndex++] =
            (p->answersArray[index].classOfRR & 0x00ff);

    buffer[bufferIndex++] =
            (p->answersArray[index].ttl & 0xff000000) >> 24;
    buffer[bufferIndex++] =
            (p->answersArray[index].ttl & 0x00ff0000) >> 16;
    buffer[bufferIndex++] =
            (p->answersArray[index].ttl & 0x0000ff00) >> 8;
    buffer[bufferIndex++] =
            (p->answersArray[index].ttl & 0x000000ff);

    buffer[bufferIndex++] =
            (p->answersArray[index].lengthOfRData & 0xff00) >> 8;
    buffer[bufferIndex++] =
            (p->answersArray[index].lengthOfRData & 0x00ff);

    buffer[bufferIndex++] =
            (customHost & 0xff000000) >> 24;
    buffer[bufferIndex++] =
            (customHost & 0x00ff0000) >> 16;
    buffer[bufferIndex++] =
            (customHost & 0x0000ff00) >> 8;
    buffer[bufferIndex++] =
            (customHost & 0x000000ff);

    *bufferLength = bufferIndex;
}

void writeDomainName(u_char *buffer,
                     u_int32_t *bufferIndex,
                     char const *domainName)
{
    u_int length, i;

    i = 0;
    while (domainName[i]) {
        if (i >= MAX_DOMAIN_LENGTH)
            printAndExit("\"writeDomainName\":"
                         "i >= MAX_DOMAIN_LENGTH");
        length = charsBeforeDot(domainName, i);
        //write length
        buffer[(*bufferIndex)++] = length;
        //write letters
        memcpy(buffer + *bufferIndex, domainName + i, length);
        //strncpy(buffer + *bufferIndex, domainName + i, length);
        *bufferIndex += length;

        i += length + 1; //next after dot
    }
    //write 00
    buffer[(*bufferIndex)++] = 0x00;
}

u_int charsBeforeDot(char const *str, u_int pos)
{
    u_int n = 0;
    while (str[pos++] != '.')
        n++;

    return n;
}

void readQuestion(struct Question * const q,
                  u_char const data[],
                  u_int * const index)
{
    readDomainName(data, index, q->domainName);

    //type of question's RR
    q->typeOfRR = data[*index] << 8 | data[*index+1];
    *index += 2;

    //class of question's RR
    q->classOfRR = data[*index] << 8 | data[*index+1];
    *index += 2;
}

void readResourceRecord(struct ResourceRecord * const r,
                        u_char const data[],
                        u_int * const index)
{
    readDomainName(data, index, r->domainName);

    r->typeOfRR = data[*index] << 8 | data[*index+1];
    *index += 2;

    r->classOfRR = data[*index] << 8 | data[*index+1];
    *index += 2;

    r->ttl = data[*index] << 24 | data[*index+1] << 16
                    | data[*index+2] << 8 | data[*index+3];
    *index += 4;

    r->lengthOfRData = data[*index] << 8 | data[*index+1];
    *index += 2;

    switch (r->typeOfRR) {
    case RR_TYPE_A:
        r->host = data[*index] << 24 | data[*index+1] << 16
                        | data[*index+2] << 8 | data[*index+3];
        break;
    default:
        printAndExit("Unimplemented RR type");
    }

    //skip RR data
    *index += r->lengthOfRData;
}


void readDomainName(u_char const data[],
                   u_int * const index,
                   char domainName[])
{
    u_int maxDomainLengthMinus1 = MAX_DOMAIN_LENGTH-1,
            charsCopied,
            domainNamePos,
            length,
            nextIndex = 0;

    //check if NAME is pointer
    if ((data[*index] & 0xC0) == 0xC0) {
        ++(*index);
        nextIndex = *index + 1;
        *index = data[*index];//go to pointed index
    }
    //read domain name
    length = data[(*index)++];
    if (length > (maxDomainLengthMinus1))
        printAndExit("Max domain length exceeded");

    domainNamePos = 0;
    while (length != 0) {
        if (length > (maxDomainLengthMinus1))
            printAndExit("Max domain length exceeded");

        for (charsCopied = 0; charsCopied < length; ++charsCopied)
            domainName[domainNamePos++] = data[(*index)++];

        length = data[(*index)++];
        domainName[domainNamePos++] = '.';
    }
    domainName[domainNamePos] = '\0';

    //restore index
    if (nextIndex != 0)
        *index = nextIndex;
}

bool domainIsBlacklisted(char *domain,
                         struct Blacklist const *blacklist)
{
    u_int i;
    for (i = 0; i < blacklist->domainsNumber; ++i)
        if (strncmp(domain, blacklist->domains[i],
                    MAX_DOMAIN_LENGTH) == 0)
            return true;

    return false;
}

bool hostIsBlacklisted(uint32_t host,
                  struct Blacklist const *blacklist)
{
    u_int i;
    for (i = 0; i < blacklist->hostsNumber; ++i)
        if (host == blacklist->hosts[i])
            return true;

    return false;
}

void destroyDNSpacket(struct DNSpacket *p)
{
    if (p->header.questionsCount > 0)
        free(p->questionsArray);
    if (p->header.answersCount > 0)
        free(p->answersArray);
    if (p->header.authorityCount > 0)
        free(p->authorityArray);
    if (p->header.additionalCount > 0)
        free(p->additionalArray);
}
