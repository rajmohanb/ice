/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2011, MindBricks Technologies               *
*                   MindBricks Confidential Proprietary.                       *
*                         All Rights Reserved.                                 *
*                                                                              *
********************************************************************************
*                                                                              *
* This document contains information that is confidential and proprietary to   *
* MindBricks Technologies. No part of this document may be reproduced in any   *
* form whatsoever without prior written approval from MindBricks Technologies. *
*                                                                              *
*******************************************************************************/

#include <unistd.h>
#include <platform_api.h>

void app_timer_callback(void *timer_id, void *arg)
{
    printf ("***********TEST Timer fired**************\n");
    return;
}

void print_bytes (uint8_t *bytes, int len)
{
    int i;

    printf ("0x");
    for (i = 0; i < len; i++)
        printf ("%02x", bytes[i]);

    printf ("\n");
}


int main (int argc, char *argv[])
{
#if 0
    int i = 0;
    void *t1, *t2, *t3;
    timer_expiry_callback cb = app_timer_callback;

    printf ("Starting the platform library test\n");

    platform_init();

    printf ("Stopping the platform library test\n");
    
    t1 = platform_start_timer(10000, cb, 0);
    t2 = platform_start_timer(5000, cb, 0);
    t3 = platform_start_timer(6000, cb, 0);
    
    if (platform_stop_timer(t1) == true)
    {
        printf ("Timer stopped\n");
    }
    else
    {
        printf ("NOT able to stop timer\n");
    }
    
    while (i < 100)
        sleep(1);
#endif
    unsigned char hmac[20];
    unsigned char key[] ="hello";
    unsigned char str[] = "world";

    platform_hmac_sha(key, 5, str, 5, hmac, 20);

    print_bytes(hmac, 20);

    return 0;
}
