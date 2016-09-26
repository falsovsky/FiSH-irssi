#include <stdio.h>
#include "blowfish.h"

char *iniKey = "blowinikey";

// NO IRSSI

//key=morte666
//key=+OK TAi1E1VGUJs1

//message=teste
//message=+OK 8qRoh/aBhUD0

int main() {
    char *clearMessage = "teste";
    char *clearKey     = "morte666";

    char cryptedMessage[100];
    char uncryptedMessage[100];

    printf("clearKey:         %s\n", clearKey);
    printf("clearMessage:     %s\n", clearMessage);

    strcpy(cryptedMessage, "+OK ");
    encrypt_string(clearKey, clearMessage, cryptedMessage + 4, strlen(clearMessage));

    printf("cryptedMessage:   %s\n", cryptedMessage);

    decrypt_string(clearKey, cryptedMessage + 4, uncryptedMessage, strlen(cryptedMessage + 4));

    printf("uncryptedMessage: %s\n", uncryptedMessage);
}