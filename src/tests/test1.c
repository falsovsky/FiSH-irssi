#include <stdio.h>
#include <assert.h>
#include "blowfish.h"

void *testClearKeyCrypt(const char *clearKey, const char *clearMessage, char *cryptedMessage) {
    strcpy(cryptedMessage, "+OK ");
    encrypt_string(clearKey, clearMessage, cryptedMessage + 4, strlen(clearMessage));
}

void testClearKeyDecrypt(const char *clearKey, const char *cryptedMessage, char *decryptedMessage) {
    decrypt_string(clearKey, cryptedMessage + 4, decryptedMessage, strlen(cryptedMessage + 4));
}

void testClearKey(const char *clearKey, const char *message, const char *assert) {
    char *cryptedMessage;
    char *decryptedMessage;

    cryptedMessage = (char *) malloc(strlen(message) * 2);
    testClearKeyCrypt(clearKey, message, cryptedMessage);
    //printf("%s\n", cryptedMessage);
    assert(strcmp(cryptedMessage, assert) == 0);

    decryptedMessage = (char *) malloc(strlen(cryptedMessage));
    testClearKeyDecrypt(clearKey, cryptedMessage, decryptedMessage);
    //printf("%s\n", decryptedMessage);
    assert(strcmp(decryptedMessage, message) == 0);

    free(cryptedMessage);
    free(decryptedMessage);
}

int main() {
    testClearKey("morte666", "teste", "+OK 8qRoh/aBhUD0");
    testClearKey("vivaobenficaglorioso",
        "ALGUM ATIVO, MASCULINO, QUE CURTA SER BEM MAMADO E COMER UM CU FIRME E REDONDINHO DE DESPORTISTA? SIGILO TOTAL",
        "+OK dLyvH1KCqym0s0hfc0n7Mew.ozzf/0MD06N1ywIA/.H4Qq.1Kbo3n0Kohah1O27E21tRcnt1nCgpe1mSyJN.unpoj.yvm0Z.elGgA.ceSTg.xmFga.tAROY.oilLa/9Tn4u0sSKkF1WSY340d54220eVDwk0vOG4K/rCAVe0");

}

