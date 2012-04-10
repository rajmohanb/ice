#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/md5.h>

static char *licensee = NULL;
static char *licensor = NULL;
static char *expdate = NULL;
static char *prod = NULL;
static char *initdate = NULL;
static char *lickey = NULL;

int read_license_file(void)
{
    char key[100], value[100];
    FILE *licf = NULL;

    licf = fopen("license.txt", "r");
    if (licf == NULL)
    {
        printf("License file is missing\n");
        return -1;
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
        else if (strncmp(key, "key", 3) == 0)
            lickey = strdup(value);
    }

    return 0;
}

int verify_license (void)
{
    MD5_CTX ctx;
    unsigned int i, j, val;
    unsigned char key[16], key1[16], *dstp;
    char *srcp;
    time_t curtime;
    struct tm *now;
    int dd, mm, yyyy;

    if (read_license_file() != 0) return -1;

    if ((expdate == NULL) || (initdate == NULL) || (lickey == NULL) ||
                (licensor == NULL) || (licensee == NULL) || (prod == NULL))
    {
        printf("License expired?\n");
        return -1;
    }

    j = strlen(lickey);
    if (j != 32)
    {
        printf("License expired?\n");
        return -1;
    }

#if 0
    printf("\n\n");

    printf("%s\n", expdate);
    printf("%s\n", initdate);
    printf("%s\n", licensor);
    printf("%s\n", licensee);
    printf("%s\n", prod);

    printf("\n\n");
#endif

    MD5_Init(&ctx);

    MD5_Update(&ctx, licensee, strlen(licensee));
    MD5_Update(&ctx, licensor, strlen(licensor));
    MD5_Update(&ctx, prod, strlen(prod));
    MD5_Update(&ctx, expdate, strlen(expdate));
    MD5_Update(&ctx, initdate, strlen(initdate));

    MD5_Final(key, &ctx);

#if 0
    printf("\n\n0x");
    for (i = 0; i < 16; i++)
    {
        printf(" %02x", key[i]);
    }
    printf("\n\n");
#endif

    dstp = key1;
    srcp = lickey;

    for (i = 0; i < j; i+=2)
    {
        sscanf(srcp, "%2x", &val);
        *dstp++ = val;
        srcp += 2;
    }

    /* compare the key with generated key */
    for (i = 0; i < 16; i++)
    {
        if (key[i] != key1[i])
        {
            printf("Keys dont match. License expired?\n");
            return -1;
        }
    }

    /** validate date */
    time(&curtime);
    now = localtime(&curtime);

    sscanf(initdate, "%d-%d-%d", &dd, &mm, &yyyy);

    if (((now->tm_year + 1900) < yyyy) || 
            ((now->tm_mon+1) < mm) || (now->tm_mday < dd))
    {
        printf("License start date invalid. License expired\n");
        return -1;
    }

    sscanf(expdate, "%d-%d-%d", &dd, &mm, &yyyy);
    //printf("%d-%d-%d\n", dd, mm, yyyy);
    //printf("%d-%d-%d\n", now->tm_mday, (now->tm_mon+1), (now->tm_year+1900));

    if (((now->tm_year + 1900) > yyyy) || 
            ((now->tm_mon+1) > mm) || ((now->tm_mday > dd) && ((now->tm_mon+1) >= mm)))
    {
        //printf("License expired, date over\n");
        return -1;
    }


    //printf("Keys matched. License still valid\n");

    return 0;
}

#if 0
int main (int argc, char *argv[])
{
    if (verify_license() == 0)
        printf("License valid\n");
    else
        printf("License invalid\n");

    return 0;
}
#endif
