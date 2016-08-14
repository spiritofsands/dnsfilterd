#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "log.h"

void cleanLog()
{
    FILE *logfile;
    logfile=fopen(LOG_FILE,"w");
    if (!logfile)
        return;
    fclose(logfile);
}

void printAndExit(char *message)
{
    logMessage(message);
    logMessage("Exiting");
    exit(1);
}

void logMessage(char *message)
{
    FILE *logfile;
    logfile=fopen(LOG_FILE,"a");
    if (!logfile)
        return;
    fprintf(logfile,"%s\n",message);
    fclose(logfile);
}

