#include <stdio.h>

FILE *openLog(char *logFileName, char mode);
void printLog(FILE *logFile, const char *fmt, ...);
void closeLog(FILE *logFile);
void setLogLevel(int level);
#define printLogLevel0(logFile, fmt, ...)\
    do { if (logManagerLevel>=0) printLog(logFile, fmt, __VA_ARGS__); } while (0)
#define printLogLevel1(logFile, fmt, ...)\
    do { if (logManagerLevel>=1) printLog(logFile, fmt, __VA_ARGS__); } while (0)
#define printLogLevel2(logFile, fmt, ...)\
    do { if (logManagerLevel>=2) printLog(logFile, fmt, __VA_ARGS__); } while (0)
#define printLogLevel3(logFile, fmt, ...)\
    do { if (logManagerLevel>=3) printLog(logFile, fmt, __VA_ARGS__); } while (0)
#define printLogLevel4(logFile, fmt, ...)\
    do { if (logManagerLevel>=4) printLog(logFile, fmt, __VA_ARGS__); } while (0)

extern FILE *LOGFILE;
