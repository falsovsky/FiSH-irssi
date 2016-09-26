#include <string.h>

/*
   Public Base64 conversion tables
   */
const char B64ABC[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char b64buf[256];

/*
   void initb64();
   Initializes the base64->base16 conversion tab.
   Call this function once when your program starts.
   and always after your B64 table has been changed.
   */
void initb64()
{
    unsigned int i;
    for (i = 0; i < 256; i++)
        b64buf[i] = 0x00;
    for (i = 0; i < 64; i++)
        b64buf[(int)(B64ABC[i])] = i;
}

/*
   int b64toh(lpBase64String, lpDestinationBuffer);
   Converts base64 string b to hexnumber d.
   Returns size of hexnumber in bytes.
   */
int b64toh(const char *b, char *d)
{
    unsigned int i, k, l;

    l = strlen(b);
    if (l < 2)
        return 0;
    for (i = l - 1; ; i--) {
        if (b64buf[(int)(b[i])] == 0)
            l--;
        else
            break;
    }

    if (l < 2)
        return 0;
    i = 0, k = 0;
    while (1) {
        i++;
        if (k + 1 < l)
            d[i - 1] = ((b64buf[(int)(b[k])]) << 2);
        else
            break;
        k++;
        if (k < l)
            d[i - 1] |= ((b64buf[(int)(b[k])]) >> 4);
        else
            break;
        i++;
        if (k + 1 < l)
            d[i - 1] = ((b64buf[(int)(b[k])]) << 4);
        else
            break;
        k++;
        if (k < l)
            d[i - 1] |= ((b64buf[(int)(b[k])]) >> 2);
        else
            break;
        i++;
        if (k + 1 < l)
            d[i - 1] = ((b64buf[(int)(b[k])]) << 6);
        else
            break;
        k++;
        if (k < l)
            d[i - 1] |= (b64buf[(int)(b[k])]);
        else
            break;
        k++;
    }
    return i - 1;
}

/*
   int htob64(lpHexNumber, lpDestinationBuffer);
   Converts hexnumber h (with length l bytes) to base64 string d.
   Returns length of base64 string.
   */
int htob64(const char *h, char *d, unsigned int l)
{
    unsigned int i, j, k;
    unsigned char m, t;

    if (!l)
        return 0;
    l <<= 3;		// no. bits
    m = 0x80;
    for (i = 0, j = 0, k = 0, t = 0; i < l; i++) {
        if (h[(i >> 3)] & m)
            t |= 1;
        j++;
        if (!(m >>= 1))
            m = 0x80;
        if (!(j % 6)) {
            d[k] = B64ABC[t];
            t &= 0;
            k++;
        }
        t <<= 1;
    }
    m = 5 - (j % 6);
    t <<= m;
    if (m) {
        d[k] = B64ABC[t];
        k++;
    }
    d[k] &= 0;
    return (int)strlen(d);
}
