#include <stdio.h>
#include <stdlib.h>

#include <ctype.h>
#include <string.h>
#include <unistd.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "rfc_structs.h"
#include "parser.h"
#include "blacklist_loader.h"
#include "log.h"


#define LOCK_FILE "dnsfilterd.lock"
#define RUNNING_DIR	"/tmp"

static struct Blacklist blacklist;

void signalHandler(int sig);

void daemonInit();

void cleanup();

int main(int argc, char *argv[])
{    
    if (argc != 3) {
        fprintf(stderr, "USAGE: %s <port> <blacklist_file>\n", argv[0]);
        exit(1);
    }

    unsigned int listeningPort = atoi(argv[1]);
    if (listeningPort == 0) {
        fprintf(stderr, "%s\n", "Port must be integer");
        exit(1);
    }

    char *blacklistFileName = argv[2];

    daemonInit();
    cleanLog();

    char *openDNShost = "208.67.222.222";
    u_int openDNSport = 53;

    logMessage("Starting server on port:");
    logMessage(argv[1]);

    readBlacklist(blacklistFileName, &blacklist);

    int localSocket, externalSocket;
    struct sockaddr_in localServer,
            externalServer;
    u_char buffer[BUFF_SIZE];
    u_int externalLen,
            localLen;
    int receivedSize = 0;

    logMessage("Setting up UDP sockets");
    const int domainType = AF_INET; //internet/IP
    const int socketType = SOCK_DGRAM; //datagrams
    const int protocol = IPPROTO_UDP;
    if ((localSocket = socket(domainType, socketType, protocol)) < 0)
        printAndExit("Failed to create local socket");
    if ((externalSocket = socket(domainType, socketType, protocol)) < 0)
        printAndExit("Failed to create external socket");

    logMessage("Constructing the sockaddr_in structures");
    memset(&localServer, 0, sizeof(localServer));     //clear struct
    localServer.sin_family = domainType;             //internet/IP
    localServer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    localServer.sin_port = htons(listeningPort);     //server port

    memset(&externalServer, 0, sizeof(externalServer));
    externalServer.sin_family = domainType;
    externalServer.sin_addr.s_addr = inet_addr(openDNShost);
    externalServer.sin_port = htons(openDNSport);

    logMessage("Binding the sockets");
    localLen = sizeof(localServer);
    if (bind(localSocket, (struct sockaddr *) &localServer, localLen) < 0)
        printAndExit("Failed to bind local server socket");
    externalLen = sizeof(externalServer);

    logMessage("Listening...");
    const int flags = 0;
    for (;;)
    {
        //Receive a message (local server)
        if ((receivedSize = recvfrom(localSocket, buffer, BUFF_SIZE, flags,
                                 (struct sockaddr *) &localServer,
                                 &localLen)) < 0)
            printAndExit("Failed to receive message from local server");

        logMessage("Local client connected:");
        logMessage(inet_ntoa(localServer.sin_addr));
        logMessage("Earned request");

        logMessage("\nSending the same message to the real DNS");
        if (sendto(externalSocket, buffer, receivedSize, 0,
                   (struct sockaddr *) &externalServer,
                   sizeof(externalServer)) != receivedSize)
            printAndExit("Mismatch in number of sent bytes");

        if ((receivedSize = recvfrom(externalSocket, buffer, BUFF_SIZE, flags,
                                 (struct sockaddr *) &externalServer,
                                 &externalLen)) < 0)
            printAndExit("Failed to receive message from external server");

        logMessage("External client connected:");
        logMessage(inet_ntoa(externalServer.sin_addr));
        logMessage("Earned answer");

        checkIfBlacklisted(buffer, &receivedSize, &blacklist);

        logMessage("\nSending the answer back");
        if (sendto(localSocket, buffer, receivedSize, flags,
                   (struct sockaddr *) &localServer,
                   localLen) != receivedSize)
            printAndExit("Mismatch in number of echo'd bytes");

        logMessage("\nSuccess");
    }

    cleanup();

    exit(EXIT_SUCCESS);
}

void daemonInit()
{
    int lockFileID, pid, sid;
    char PIDstr[10];

    if(getppid()==1) //already a daemon
        return;

    pid = fork();
    if (pid < 0) //fork error
            exit(EXIT_FAILURE);

    //exit the parent process.
    if (pid > 0)
            exit(EXIT_SUCCESS);

    //change the file mode mask
    umask(027);

    //a new SID for the child process
    sid = setsid();
    if (sid < 0)
            exit(EXIT_FAILURE);

    if ((chdir(RUNNING_DIR)) < 0)
            exit(EXIT_FAILURE);

    lockFileID = open(LOCK_FILE, O_RDWR|O_CREAT, 0640);
    if (lockFileID < 0)
        exit(1); //can't open
    if (lockf(lockFileID, F_TLOCK, 0) < 0)
        exit(0); //can't lock

    sprintf(PIDstr, "%d\n", getpid());
    write(lockFileID, PIDstr, strlen(PIDstr));

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    signal(SIGCHLD,SIG_IGN); //ignore child
    signal(SIGTSTP,SIG_IGN); //ignore tty signals
    signal(SIGTTOU,SIG_IGN);
    signal(SIGTTIN,SIG_IGN);
    signal(SIGHUP,signalHandler); //catch hangup signal
    signal(SIGTERM,signalHandler); //catch kill signal

    logMessage("Daemon started");
}

void signalHandler(int signal)
{
    switch(signal) {
    case SIGHUP:
        logMessage("\nHangup signal catched");
        cleanup();
        exit(0);
        break;
    case SIGTERM:
        logMessage("\nTerminate signal catched");
        cleanup();
        exit(0);
        break;
    }
}

void cleanup()
{
    freeBlacklistMemory(&blacklist);
}
