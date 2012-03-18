#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <string.h>

int logManagerLevel = 0;
FILE *LOGFILE;

#include "logManager.h"

void setLogLevel(int level)
{
    if(level>=0 && level<5)
        logManagerLevel = level;
    return;
}

/*+----------------------------------------------------------+
  | Function name : openLog                                  |
  | Parameters    :                                          |
  |        in     : A string containing the name for the log |
  |               : file.                                    |
  |               : mode could assume the following values:  |
  |               : 'a' or 'w', if mode = 'a' the logManager |
  |               : will append the printLog information     |
  |               : to the file logFileName, otherwise the   |
  |               : logManager will create a new log file.   |
  |               : if mode = 'o' the output will be         |
  |               : redirected to the standard output.       |
  |               : if mode = 'e' the output will be         |
  |               : redirected to the standard error.        |
  | Return  value : The pointer to the new file              |
  | Description   : opens a new file for logging.            |
  +----------------------------------------------------------+*/
FILE *openLog(char *logFileName, char mode)
{
    FILE    *logFile;

	switch(mode)
	{
		case 'a':
			logFile = fopen(logFileName, "a");
			break;
		case 'w':
			logFile = fopen(logFileName, "w");
			break;
		case 'o':
			logFile = stdout;
			break;
		case 'e':
			logFile = stderr;
			break;
		default:
			logFile = NULL;
			fprintf(stderr, "mode is unknown");
			break;
	}
	if (logFile == NULL)
	{
		fprintf(stderr, "Unable to open %s file for writing: %s.\n", logFileName, strerror(errno));
		fprintf(stderr, "All printLog will be redirected to stderr.\n");
	}

	return(logFile);
}


/*+----------------------------------------------------------+
  | Function name : printLog                                 |
  | Parameters    :                                          |
  |        in     : The logFile pointer (could be NULL).     |
  |        fmt    : A variable length format string.         |
  | Return  value : NONE                                     |
  | Description   : Prints a line into the logFile           |
  +----------------------------------------------------------+*/
void printLog(FILE *logFile, const char *fmt, ...)
{
	va_list      ap;
	time_t       t;
	char         datestr[51];

	t = time(NULL);
	tzset();
	strftime(datestr, sizeof(datestr) - 1, "%a %b %d %T %Z %Y", localtime(&t));
	if(logFile==NULL)
	{
        fprintf(stderr, "%s [%d] :", datestr, getpid());
    }
    else
    {
        fprintf(logFile, "%s [%d] :", datestr, getpid());
    }
	va_start(ap, fmt);
	if(logFile==NULL)
	{
        vfprintf(stderr, fmt, ap);
    }
    else
    {
        vfprintf(logFile, fmt, ap);
    }
	va_end(ap);
	if(logFile==NULL)
	{
	    fprintf(stderr, "\n");
    }
    else
    {
        fprintf(logFile, "\n");
    }
	if(fflush(logFile)!=0)
	{
		perror("Cannot fflush logFile");
	}
	return;
}

/*+----------------------------------------------------------+
  | Function name : closeLog                                 |
  | Parameters    :                                          |
  |        in     : The file pointer to close.               |
  | Return  value : NONE                                     |
  | Description   : closes the log file if we aren't using   |
  |  the stderr as destination.                              |
  +----------------------------------------------------------+*/
void closeLog(FILE *logFile)
{
	printLog(logFile, "Closing the log file.\n");
	if(logFile!=NULL)
    {
		if(fclose(logFile)!=0)
		{
			perror("Closing the logFile");
		}
	}
	return;
}

