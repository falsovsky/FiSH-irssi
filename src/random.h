#ifndef RANDOM_H_
#define RANDOM_H_

#include <stddef.h>

// Returns 0 if ok, and a negative number otherwise.
int random_read (unsigned char* dest, size_t n);

#endif // RANDOM_H_
