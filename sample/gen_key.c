#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>

char *licensee = NULL;
char *licensor = NULL;
char *expdate = NULL;
char *prod = NULL;
char *initdate = NULL;
char *lickey = NULL;

void read_license_file(void)
{
    char key[100], value[100];
    FILE *licf = NULL;

    licf = fopen("license.txt", "r");
    if (licf == NULL)
    {
        printf("License file is missing\n");
        return;
    }

    while(!feof(licf))
    {
        fscanf(licf, "%s %s", key, value);

        //printf("KEY: [%s] VALUE: [%s]\n", key, value);

        if (strncmp(key, "expiry-date", 11) == 0)
            expdate = strdup(value);
        else if (strncmp(key, "licensed-date", 13) == 0)
            initdate = strdup(value);
        else if (strncmp(key, "licensor", 8) == 0)
            licensor = strdup(value);
        else if (strncmp(key, "licensee", 8) == 0)
            licensee = strdup(value);
        else if (strncmp(key, "product", 7) == 0)
            prod = strdup(value);
    }

    return;
}

int main (int argc, char *argv[])
{
    MD5_CTX ctx;
    unsigned char key[16];
    int i;

    read_license_file();

    if ((expdate == NULL) || (initdate == NULL) ||
            (licensor == NULL) || (licensee == NULL) || (prod == NULL))
    {
        printf("License expired?\n");
        return 0;
    }

    printf("\n\n");

    printf("%s\n", expdate);
    printf("%s\n", initdate);
    printf("%s\n", licensor);
    printf("%s\n", licensee);
    printf("%s\n", prod);

    printf("\n\n");

    MD5_Init(&ctx);

    MD5_Update(&ctx, licensee, strlen(licensee));
    MD5_Update(&ctx, licensor, strlen(licensor));
    MD5_Update(&ctx, prod, strlen(prod));
    MD5_Update(&ctx, expdate, strlen(expdate));
    MD5_Update(&ctx, initdate, strlen(initdate));

    MD5_Final(key, &ctx);

    printf("\n\n0x");
    for (i = 0; i < 16; i++)
    {
        printf(" %02x", key[i]);
    }
    printf("\n\n");

    return 0;
}
