#ifndef RFC_STRUCTS_H
#define RFC_STRUCTS_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_DOMAIN_LENGTH 64
#define BUFF_SIZE 512

enum opCodeTypes {
    OPCODE_QUERY,  //0
    OPCODE_IQUERY,
    OPCODE_STATUS
    //3-15 are reserved for future use
};

enum responseCodeTypes {
    RESPONSE_NO_ERROR, //0
    RESPONSE_FORMAT_ERROR,
    RESPONSE_SERVER_FAILURE,
    RESPONSE_NAME_ERROR,
    RESPONSE_NOT_IMPLEMENTED,
    RESPONSE_REFUSED
    //6-15 are reserved for future use
};

enum ResourceRecordType {
    RR_TYPE_A = 1,
    RR_TYPE_NS,
    RR_TYPE_MD,
    RR_TYPE_MF,
    RR_TYPE_CNAME,
    RR_TYPE_SOA,
    RR_TYPE_MB,
    RR_TYPE_MG,
    RR_TYPE_MR,
    RR_TYPE_NULL,
    RR_TYPE_WKS,
    RR_TYPE_PTR,
    RR_TYPE_HINFO,
    RR_TYPE_MINFO,
    RR_TYPE_MX,
    RR_TYPE_TXT,
    RR_TYPE_AXFR = 252,
    RR_TYPE_MAILB,
    RR_TYPE_MAILA,
    RR_TYPE_ALL
};

enum ResourceRecordClass {
    RR_CLASS_IN = 1,
    RR_CLASS_CS,
    RR_CLASS_CH,
    RR_CLASS_HS,
    RR_CLASS_ALL = 255
};

struct Header
{
    uint16_t id;
    bool isResponse;
    uint8_t opCode; //opCodeTypes
    bool isAuthoritativeAnswer;
    bool isTruncated;
    bool isRecursionDesired;
    bool isRecursionAvailable;
    char z;
    uint8_t responseCode; //responseCodeTypes

    uint16_t questionsCount;
    uint16_t answersCount;
    uint16_t authorityCount;
    uint16_t additionalCount;
};

void printHeader(struct Header const * const h);

struct Question
{
    char domainName[MAX_DOMAIN_LENGTH+1];    //64 + '\0'
    uint16_t typeOfRR; //ResourceRecordType
    uint16_t classOfRR; //ResourceRecordClass
};

void printQuestion(struct Question const * const q);

struct ResourceRecord
{
    char domainName[MAX_DOMAIN_LENGTH+1];
    uint16_t typeOfRR; //ResourceRecordType
    uint16_t classOfRR; //ResourceRecordClass
    uint32_t ttl;
    uint16_t lengthOfRData;
    uint32_t host;
};

void printResourceRecord(struct ResourceRecord const * const r);

#endif // RFC_STRUCTS_H
