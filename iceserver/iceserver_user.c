/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2012, MindBricks Technologies               *
*                  Rajmohan Banavi (rajmohan@mindbricks.com)                   *
*                     MindBricks Confidential Proprietary.                     *
*                            All Rights Reserved.                              *
*                                                                              *
********************************************************************************
*                                                                              *
* This document contains information that is confidential and proprietary to   *
* MindBricks Technologies. No part of this document may be reproduced in any   *
* form whatsoever without prior written approval from MindBricks Technologies. *
*                                                                              *
*******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

#include <stdio.h>

#include <stun_base.h>



void *mb_iceserver_decision_thread(void *arg)
{
    int bytes, ret;
    int sock = (int)arg;
    char buf[1500];

    printf("In am in the decision thread now\n");
    printf("Unix domain socket is : %d\n", sock);

    /** get into loop */
    while(1)
    {
        bytes = recvfrom(sock, buf, 1500, 0, NULL, NULL);

        printf("Got something to process %d bytes\n", bytes);
    }

    return NULL;
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/

