#ifndef PRINTANDEXIT_H
#define PRINTANDEXIT_H

#include <stdio.h>
#define LOG_FILE "dnsfilterd.log"

void cleanLog();
void logMessage(char *message);
void printAndExit(char *message);

#endif //PRINTANDEXIT_H
