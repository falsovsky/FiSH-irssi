#include <stdlib.h>
#include <stdio.h>
#include "log.h"

bool LogCreated = false;

void Log (char* message, char *object, char *format)
{
    FILE *file;

    if (!LogCreated) {
        file = fopen(LOGFILE, "w");
        LogCreated = true;
    }
    else
        file = fopen(LOGFILE, "a");

    if (file == NULL) {
        if (LogCreated)
            LogCreated = false;
        return;
    }
    else
    {
        fputs(message, file);
        fputs(" - ", file);
        fprintf(file, object, format);
        fclose(file);
    }

    if (file)
        fclose(file);
}

void LogErr (char *message)
{
    Log(message);
    Log("\n");
}
