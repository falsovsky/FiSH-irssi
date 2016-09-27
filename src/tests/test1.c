#include <stdio.h>
#include <assert.h>
#include "blowfish.h"

void plainKeyCrypt(const char *plainKey, const char *clearMessage, char *cryptedMessage) {
    strcpy(cryptedMessage, "+OK ");
    encrypt_string(plainKey, clearMessage, cryptedMessage + 4, strlen(clearMessage));
}

void plainKeyDecrypt(const char *plainKey, const char *cryptedMessage, char *decryptedMessage) {
    decrypt_string(plainKey, cryptedMessage + 4, decryptedMessage, strlen(cryptedMessage + 4));
}

void testPlainKey(const char *plainKey, const char *plainMessage, const char *assert) {
    char *cryptedMessage;
    char *decryptedMessage;
    int plainSize = strlen(plainMessage);
    int cryptedSize;

    //printf("plainSize: %d\n", plainSize);
    cryptedSize = ((((plainSize + 8) & ~(0x7)) + ((plainSize / 8))) / 3 + 1) * 4 + 5;
    //printf("calculatedSize: %d\n", cryptedSize);

    cryptedMessage = (char *) malloc(cryptedSize);
    //cryptedMessage = (char *) malloc(500);
    plainKeyCrypt(plainKey, plainMessage, cryptedMessage);
    //printf("realSize: %lu\n", strlen(cryptedMessage));
    //printf("%s\n", cryptedMessage);
    assert(strcmp(cryptedMessage, assert) == 0);

    decryptedMessage = (char *) malloc(plainSize);
    plainKeyDecrypt(plainKey, cryptedMessage, decryptedMessage);
    //printf("%s\n", decryptedMessage);
    assert(strcmp(decryptedMessage, plainMessage) == 0);

    free(cryptedMessage);
    free(decryptedMessage);
}

void testCryptedKey(const char *cryptedKey, const char *iniKey, const char *plainMessage, const char *assert) {

}

int main() {
    testPlainKey("morte666", "teste", "+OK 8qRoh/aBhUD0");
    testPlainKey("vivaobenficaglorioso",
        "ALGUM ATIVO, MASCULINO, QUE CURTA SER BEM MAMADO E COMER UM CU FIRME E REDONDINHO DE DESPORTISTA? SIGILO TOTAL",
        "+OK dLyvH1KCqym0s0hfc0n7Mew.ozzf/0MD06N1ywIA/.H4Qq.1Kbo3n0Kohah1O27E21tRcnt1nCgpe1mSyJN.unpoj.yvm0Z.elGgA.ceSTg.xmFga.tAROY.oilLa/9Tn4u0sSKkF1WSY340d54220eVDwk0vOG4K/rCAVe0");
    //vivaobenficaglorioso
    //testPlainKey("")
}

