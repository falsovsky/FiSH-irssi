#include <stdlib.h>
#include <stdio.h>
#include "log.h"

int LogCreated = 0;

void Log(char* message, char *object, char *format)
{
    FILE *file;

    if (LogCreated == 0) {
        file = fopen(LOGFILE, "w");
        LogCreated = 1;
    }
    else
        file = fopen(LOGFILE, "a");

    if (file == NULL) {
        if (LogCreated == 1)
            LogCreated = 0;
        return;
    }
    else
    {
        fputs(message, file);
        fputs(" - ", file);
        fprintf(file, object, format);
       fputs("\n", file);
        fclose(file);
    }

    if (file)
        fclose(file);
}

void LogErr(char *message)
{
/*
    Log(message);
    Log("\n");
*/
}
