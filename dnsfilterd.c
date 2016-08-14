#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "rfc_structs.h"
#include "parser.h"
#include "blacklist_loader.h"
#include "printAndExit.h"

static const int listeningPort = 5300;

int main(int argc, char *argv[])
{    
    char *openDNShost = "208.67.222.222";
    u_int openDNSport = 53;
    char *blacklistFileName = "blacklist";
    struct Blacklist blacklist;

    puts("Starting server");

    readBlacklist(blacklistFileName, &blacklist);

    int localSocket, externalSocket;
    struct sockaddr_in localServer,
            externalServer;
    u_char buffer[BUFF_SIZE];
    u_int externalLen,
            localLen;
    int receivedSize = 0;

    puts("Setting up UDP sockets");
    const int domainType = AF_INET; //internet/IP
    const int socketType = SOCK_DGRAM; //datagrams
    const int protocol = IPPROTO_UDP;
    if ((localSocket = socket(domainType, socketType, protocol)) < 0)
        printAndExit("Failed to create local socket");
    if ((externalSocket = socket(domainType, socketType, protocol)) < 0)
        printAndExit("Failed to create external socket");

    puts("Constructing the sockaddr_in structures");
    memset(&localServer, 0, sizeof(localServer));     //clear struct
    localServer.sin_family = domainType;             //internet/IP
    localServer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    localServer.sin_port = htons(listeningPort);     //server port

    memset(&externalServer, 0, sizeof(externalServer));
    externalServer.sin_family = domainType;
    externalServer.sin_addr.s_addr = inet_addr(openDNShost);
    externalServer.sin_port = htons(openDNSport);

    puts("Binding the sockets");
    localLen = sizeof(localServer);
    if (bind(localSocket, (struct sockaddr *) &localServer, localLen) < 0)
        printAndExit("Failed to bind local server socket");
    externalLen = sizeof(externalServer);

    puts("Listening...");
    const int flags = 0;
    for (;;)
    {
        //Receive a message (local server)
        if ((receivedSize = recvfrom(localSocket, buffer, BUFF_SIZE, flags,
                                 (struct sockaddr *) &localServer,
                                 &localLen)) < 0)
            printAndExit("Failed to receive message from local server");

        printf("Local client connected: %s\n",
               inet_ntoa(localServer.sin_addr));
        puts("Earned request");

//        if ( isBlacklistedMessage(buffer, &blacklist) )
//            puts("\nIS BLACKLISTED");

        puts("\nSending the same message to the real DNS");
        if (sendto(externalSocket, buffer, receivedSize, 0,
                   (struct sockaddr *) &externalServer,
                   sizeof(externalServer)) != receivedSize)
            printAndExit("Mismatch in number of sent bytes");

        if ((receivedSize = recvfrom(externalSocket, buffer, BUFF_SIZE, flags,
                                 (struct sockaddr *) &externalServer,
                                 &externalLen)) < 0)
            printAndExit("Failed to receive message from external server");

        printf("External client connected: %s\n",
               inet_ntoa(externalServer.sin_addr));
        puts("Earned answer");

        checkIfBlacklisted(buffer, &receivedSize, &blacklist);

        puts("\nSending the answer back");
        if (sendto(localSocket, buffer, receivedSize, flags,
                   (struct sockaddr *) &localServer,
                   localLen) != receivedSize)
            printAndExit("Mismatch in number of echo'd bytes");

        puts("\nSuccess");
    }

    freeBlacklistMemory(&blacklist);
}
