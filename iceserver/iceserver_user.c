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
#include <turns_api.h>
#include <ice_server.h>


extern mb_ice_server_t g_mb_server;

static char *mb_transports[] = 
{
    "ICE_TRANSPORT_UDP",
    "ICE_TRANSPORT_TCP"
};


static void dummy_go(void)
{
    /** this is just for making use of breakpoint, to be deleted later */
    return;
}


void *mb_iceserver_decision_thread(void)
{
    int bytes, ret;
    mb_ice_server_new_alloc_t newalloc;
    mb_ice_server_alloc_decision_t decision;
    stun_MD5_CTX ctx;

    printf("In am in the decision thread now\n");
    printf("Unix domain socket is : %d\n", g_mb_server.thread_sockpair[1]);

    /** get into loop */
    while(1)
    {
        memset(&newalloc, 0, sizeof(newalloc));
        bytes = recv(g_mb_server.thread_sockpair[1], 
                            &newalloc, sizeof(newalloc), 0);

        dummy_go();

        printf ("Got an allocation request to approve\n");

        printf ("USERNAME: %s\n", newalloc.username);
        printf ("   REALM: %s\n", newalloc.realm);
        printf ("LIFETIME: %d\n", newalloc.lifetime);
        printf ("PROTOCOL: %s\n", mb_transports[newalloc.protocol]);

        /** 
         * need to check the following:
         * 1. username is valid?
         * 2. realm is valid for the username?
         * 3. check at the requested lifetime? suggest provisioned one
         * 4. And look at protocol?
         * 5. check if the user has already reached max number of allocations?
         * 6. check if the user has already reached the max number of concurrent allocations?
         * 7. Check the bandwidth usage?
         */

        /** Then decide to either approve or reject the allocation request */

        /** TODO - for now, just go ahead and approve the allocation */
        memset(&decision, 0, sizeof(decision));
        decision.blob = newalloc.blob;
        decision.approved = true;
        decision.lifetime = 1800;
        decision.code = 0;

        /** calculate the hmac key for long-term authentication */
        stun_MD5_Init(&ctx);
        stun_MD5_Update(&ctx, 
                newalloc.username, strlen((char *)newalloc.username));
        stun_MD5_Update(&ctx, ":", 1);

        stun_MD5_Update(&ctx, newalloc.realm, strlen((char *)newalloc.realm));
        stun_MD5_Update(&ctx, ":", 1);

        stun_MD5_Update(&ctx, "password", 8);

        stun_MD5_Final((u_char *)decision.hmac_key, &ctx);

        /** post */
        bytes = send(g_mb_server.thread_sockpair[1], 
                            &decision, sizeof(decision), 0);
        printf ("Sent [%d] bytes to signaling process\n", bytes);

        if (bytes)
            printf("Allocation approved\n");
        else
            printf("Allocation has been rejected\n");
    }

    return NULL;
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/

