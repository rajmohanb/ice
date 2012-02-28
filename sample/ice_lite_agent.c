/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2012, MindBricks Technologies               *
*                  Copyright (C) 2009-2012, Rajmohan Banavi                    *
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


/*******************************************************************************
*                                                                              *
* This sample application shows how the ICE stack can be used to develop an    *
* ice-lite agent application.                                                  *
*                                                                              *
*******************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ctype.h>
#include <msg_layer_api.h>
#include <stun_enc_dec_api.h>
#include <stun_txn_api.h>
#include "ice_api.h"


//#define ICE_IPV6
//#define ICE_TEST_RFC3484


//#define STUN_SRV_IP "198.65.166.165"
//#define STUN_SRV_IP "75.101.138.128"
//#define STUN_SRV_IP "216.146.46.55"
#ifdef ICE_IPV6
#define STUN_SRV_IP "2001:db8:0:242::67"
#else
#define STUN_SRV_IP "192.168.1.2"
#endif
#define STUN_SRV_PORT 3478

#define TRANSPORT_MTU_SIZE  1500
#define AGENT1_USER_NAME "outgoing"
#define AGENT1_PASSWORD "password"
#define AGENT_DOMAIN "domain.org"

#ifdef ICE_IPV6
#define LOCAL_IP   "2001:db8:0:242::67"
#else
#define LOCAL_IP   "192.168.1.2"
#endif

#define LOCAL_AUDIO_ICE_RTP_PORT 44444
#define LOCAL_AUDIO_ICE_RTCP_PORT 44445
#define LOCAL_VIDEO_ICE_RTP_PORT 55554
#define LOCAL_VIDEO_ICE_RTCP_PORT 55555

handle h_inst, h_session;
static int sockfd_sip = 0;
bool g_gather_done = false;
bool g_cc_done = false;
int sockfd_ice[4] = {0}, num_fds = 0;
u_char *my_buf;

stun_log_level_t g_log_sev = LOG_SEV_DEBUG;

char *states[] =
{
    "ICE_GATHERED",
    "ICE_CC_RUNNING",
    "ICE_CC_COMPLETED",
    "ICE_CC_FAILED",
};

void app_log(/** char *file_name, uint32_t line_num, */
                stun_log_level_t level, char *format, ...)
{
    char buff[150];
    va_list args;

    if (level > g_log_sev) return;

    va_start(args, format );
    sprintf(buff, "%s\n", format);
    vprintf(buff, args );
    va_end(args );
}


void app_timer_expiry_cb (void *timer_id, void *arg)
{
    int32_t status;

    app_log (LOG_SEV_DEBUG, "in sample application timer callback");

    /** inject timer message */
    status = ice_session_inject_timer_event(timer_id, arg);
    if (status == STUN_TERMINATED)
    {
        app_log (LOG_SEV_INFO, "ice_session_inject_timer_event() returned failure");
    }

    return;
}

int32_t app_nwk_send_msg (u_char *buf, uint32_t buf_len, 
                    stun_inet_addr_type_t ip_addr_type, u_char *ip_addr,
                    uint32_t port, handle param)
{
    int sent_bytes = 0;
    int sock_fd = (int) param;

    if (ip_addr_type == STUN_INET_ADDR_IPV4)
    {
        sent_bytes = platform_socket_sendto(sock_fd, buf, 
                            buf_len, 0, AF_INET, port, (char *)ip_addr);
    } 
    else if (ip_addr_type == STUN_INET_ADDR_IPV6) 
    {
        sent_bytes = platform_socket_sendto(sock_fd, buf, 
                            buf_len, 0, AF_INET6, port, (char *)ip_addr);
    }
    else
    {
        app_log (LOG_SEV_INFO, 
                "Invalid IP address family type. Sending of STUN message failed");
    }

    return sent_bytes;
}

handle app_start_timer (uint32_t duration, handle arg)
{
    timer_expiry_callback timer_cb = app_timer_expiry_cb;

    return platform_start_timer(duration, timer_cb, arg);
}

int32_t app_stop_timer (handle timer_id)
{
    if (platform_stop_timer(timer_id) == true)
        return STUN_OK;
    else
        return STUN_NOT_FOUND;
}


static void encode_session(handle h_inst, handle h_session)
{
    char *p, buffer[1500];
    int media_count, comp_count, cand_count;
    ice_session_params_t session_desc;
    ice_media_params_t *media_desc;
    ice_media_comp_t *media_comp;

    p = buffer;

    printf ("\n\nsend this sdp to the peer agent\n");

    printf (">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");

    ice_session_get_session_params(h_inst, h_session, &session_desc);

    /* Write "dummy" SDP v=, o=, s=, and t= lines */
    printf("v=0\no=- 3414564553 3414923132 IN IP4 localhost\ns=ice\nt=0 0\n");

    if(session_desc.ice_mode == ICE_MODE_LITE)
        printf("a=ice-lite\n");

    for (media_count = 0; media_count < session_desc.num_media; media_count++)
    {
        media_desc = &session_desc.media[media_count];

        //printf ("------------------------------------------------------------------\n");
        //printf ("Media handle %p\n", media_desc->h_media);
        //printf ("Media state: %s\n\n", states[media_desc->media_state]);

        /* Write the a=ice-ufrag and a=ice-pwd attributes */
        printf("a=ice-ufrag:%.*s\na=ice-pwd:%.*s\n",
           strlen(media_desc->ice_ufrag),
           media_desc->ice_ufrag,
           strlen(media_desc->ice_pwd),
           media_desc->ice_pwd);

        for (comp_count = 0; comp_count < media_desc->num_comps; comp_count++)
        {
            media_comp = &media_desc->comps[comp_count];

            //printf ("Media component ID: %d\n", media_comp->comp_id);
            /** log the default candidate for each component */
            if (media_comp->comp_id == RTP_COMPONENT_ID)
            {
                if (media_comp->default_dest.host_type == STUN_INET_ADDR_IPV4)
                    printf ("c=IN IP4 %s\n", media_comp->default_dest.ip_addr);
                else if (media_comp->default_dest.host_type == STUN_INET_ADDR_IPV6)
                    printf ("c=IN IP6 %s\n", media_comp->default_dest.ip_addr);
                else
                {
                    printf ("Invalid IP address type... ERROR\n");
                    break;
                }
                printf ("m=audio %d RTP/AVP 0\n", media_comp->default_dest.port);
            }
            else if (media_comp->comp_id == RTCP_COMPONENT_ID)
            {
                if (media_comp->default_dest.host_type == STUN_INET_ADDR_IPV4)
                    printf ("a=rtcp:%d IN IP4 %s\n", 
                                    media_comp->default_dest.port, 
                                    media_comp->default_dest.ip_addr);
                else if (media_comp->default_dest.host_type == STUN_INET_ADDR_IPV6)
                    printf ("a=rtcp:%d IN IP6 %s\n", 
                                    media_comp->default_dest.port, 
                                    media_comp->default_dest.ip_addr);
                else 
                {
                    printf ("Invalid host IP address type... ERROR\n");
                    break;
                }
            }
            else
            {
                printf ("Invalid COMPONENT ID...ERROR\n\n\n");
                break;
            }

            for (cand_count = 0; 
                    cand_count < media_comp->num_cands; cand_count++)
            {
                ice_cand_params_t *cand = &media_comp->cands[cand_count];

                if (cand->cand_type == ICE_CAND_TYPE_INVALID) continue;

                printf ("a=candidate:%s %u", cand->foundation, cand->component_id);
                if (cand->protocol == ICE_TRANSPORT_UDP)
                    printf (" UDP");
                else if (cand->protocol == ICE_TRANSPORT_TCP)
                    printf (" TCP");

                printf (" %lld %s %d",  cand->priority, 
                                        cand->ip_addr, cand->port);

                if (cand->cand_type == ICE_CAND_TYPE_HOST)
                    printf (" typ host\n"); 
                else if (cand->cand_type == ICE_CAND_TYPE_SRFLX)
                    printf (" typ srflx"); 
                else if (ICE_CAND_TYPE_RELAYED == cand->cand_type)
                    printf (" typ relay"); 
                else if (ICE_CAND_TYPE_PRFLX == cand->cand_type)
                    printf (" typ prflx"); 
                else
                    printf ("Invalid ICE candidate type\n");

                if (cand->cand_type != ICE_CAND_TYPE_HOST)
                    printf (" raddr %s rport %d\n", 
                                cand->rel_addr, cand->rel_port);
            }

            for (cand_count = 0; 
                    cand_count < media_comp->num_remote_cands; cand_count++)
            {
                stun_inet_addr_t *rem = &media_comp->remote_cands[cand_count];

                if((rem->host_type == STUN_INET_ADDR_IPV4) || 
                        (rem->host_type == STUN_INET_ADDR_IPV6))
                {
                    printf ("a=remote-candidates:%d %s %d\n", 
                            media_comp->comp_id, rem->ip_addr, rem->port);
                }
                else
                {
                    printf ("Invalid Remote address type.... Error\n");
                    break;
                }
            }
        }
    }

    printf ("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
}



static void ice_lite_input_remote_sdp(handle h_inst, handle h_session, handle h_media)
{
    char linebuf[160];
    unsigned media_cnt = 0;
    unsigned comp0_port = 0;
    char     comp0_addr[80];
    bool done = false;
    ice_session_params_t peer_session_desc;
    ice_media_params_t *media;
    ice_media_comp_t *comp;
    ice_cand_params_t *cand;
    int port, status;
    char net[32], ip[64];

    puts("Paste SDP from remote host, end with empty line");

    memset(&peer_session_desc, 0, sizeof(peer_session_desc));

    peer_session_desc.ice_mode = ICE_MODE_FULL;
    peer_session_desc.num_media = 1;
    media = &peer_session_desc.media[0];

    media->h_media = h_media;
    media->num_comps = 2;

    comp0_addr[0] = '\0';

    while (!done) {
        int len;
        char *line;

        printf(">");
        if (stdout) fflush(stdout);

        memset(linebuf, 0, 160);

        if (fgets(linebuf, sizeof(linebuf), stdin)==NULL)
            break;

        len = strlen(linebuf);
        while (len && (linebuf[len-1] == '\r' || linebuf[len-1] == '\n'))
            linebuf[--len] = '\0';

        line = linebuf;
        while (len && isspace(*line))
            ++line, --len;

        if (len==0)
            break;

        /* Ignore subsequent media descriptors */
        if (media_cnt > 1)
            continue;

        switch (line[0]) {
        case 'm':
            {
            int cnt;
            char media[32], portstr[32];

            ++media_cnt;
            if (media_cnt > 1) {
                puts("Media line ignored");
                break;
            }

            cnt = sscanf(line+2, "%s %s RTP/", media, portstr);
            if (cnt != 2) {
                app_log(LOG_SEV_ERROR, "Error parsing media line");
                goto on_error;
            }

            comp0_port = atoi(portstr);
            
            }
            break;
        case 'c':
            {
            int cnt;
            char c[32], net[32], ip[80];
            
            cnt = sscanf(line+2, "%s %s %s", c, net, ip);
            if (cnt != 3) {
                app_log(LOG_SEV_ERROR, "Error parsing connection line");
                goto on_error;
            }

            strcpy(comp0_addr, ip);
            }
            break;
        case 'a':
            {
            char *attr = strtok(line+2, ": \t\r\n");
            if (strcmp(attr, "ice-ufrag")==0) {
                strcpy(media->ice_ufrag, attr+strlen(attr)+1);
            } else if (strcmp(attr, "ice-pwd")==0) {
                strcpy(media->ice_pwd, attr+strlen(attr)+1);
            } else if (strcmp(attr, "ice-lite")==0) {
                peer_session_desc.ice_mode = ICE_MODE_LITE;
                app_log(LOG_SEV_INFO, "PEER is ice lite");
            } else if (strcmp(attr, "rtcp")==0) {
                char *val = attr+strlen(attr)+1;
                int cnt;

                cnt = sscanf(val, "%d IN %s %s", &port, net, ip);
                if (cnt != 3) {
                    app_log(LOG_SEV_ERROR, "Error parsing rtcp attribute");
                    goto on_error;
                }
            } else if (strcmp(attr, "candidate")==0) {
                char *sdpcand = attr+strlen(attr)+1;
                int cnt;
                char foundation[32], transport[12], ipaddr[80], type[32];
                int comp_id, prio, port;

                cnt = sscanf(sdpcand, "%s %d %s %d %s %d typ %s",
                     foundation,
                     &comp_id,
                     transport,
                     &prio,
                     ipaddr,
                     &port,
                     type);
                if (cnt != 7) {
                    printf ("error: Invalid ICE candidate line");
                    goto on_error;
                }

                comp = &media->comps[comp_id - 1];
                comp->comp_id = comp_id;

                cand = &comp->cands[comp->num_cands];

                comp->num_cands++;
                
                if (strcmp(type, "host")==0)
                    cand->cand_type = ICE_CAND_TYPE_HOST;
                else if (strcmp(type, "srflx")==0)
                    cand->cand_type = ICE_CAND_TYPE_SRFLX;
                else if (strcmp(type, "relay")==0)
                    cand->cand_type = ICE_CAND_TYPE_RELAYED;
                else {
                    printf ("Error: invalid candidate type '%s'", type);
                    goto on_error;
                }

                cand->component_id = comp_id;
                strcpy((char *)cand->foundation, foundation);
                cand->priority = prio;

                cand->protocol = ICE_TRANSPORT_UDP;
                
#ifdef ICE_IPV6
                cand->ip_addr_type = STUN_INET_ADDR_IPV6;
#else
                cand->ip_addr_type = STUN_INET_ADDR_IPV4;
#endif
                strcpy((char *)cand->ip_addr, ipaddr);
                cand->port = port;

            }
            }
            break;
        }
    }

    if (comp0_port==0 || comp0_addr[0]=='\0') {
	    printf("Error: default address for component 0 not found\n");
	    goto on_error;
    }

    status = ice_session_set_peer_session_params(
                                    h_inst, h_session, &peer_session_desc);
    if (status != STUN_OK)
    {
        app_log (LOG_SEV_ERROR, 
                "ice_session_set_peer_session_params() returned error %d\n", 
                status);
    }

    printf ("Done, remote candidate(s) added\n");

on_error:
    return;
}



void ice_lite_sample_print_valid_list(handle h_inst, handle h_session)
{
    int32_t status, i, j;
    ice_valid_pair_t *pair;
    ice_session_valid_pairs_t valid_list;
    ice_media_valid_pairs_t *valid_media;

    status = ice_session_get_session_valid_pairs(h_inst, h_session, &valid_list);
    if (status != STUN_OK)
    {
        app_log (LOG_SEV_ERROR, 
                "Unable to get the valid list for media\n");
        return;
    }

    app_log (LOG_SEV_INFO, "Number of media %d\n", valid_list.num_media);
    for (i = 0; i < valid_list.num_media; i++)
    {
        valid_media = &valid_list.media_list[i];

        app_log (LOG_SEV_INFO, 
                "Number of valid pairs %d\n", valid_media->num_valid);
        app_log (LOG_SEV_INFO, "VALID LIST\n");

        for (j = 0; j < valid_media->num_valid; j++)
        {
            pair = &valid_media->pairs[j];
            app_log (LOG_SEV_INFO, "\ncomp id: %d local: %s:%d peer: %s:%d", 
                    pair->comp_id, pair->local.ip_addr, pair->local.port,
                    pair->peer.ip_addr, pair->peer.port);
            if (pair->nominated == true)
                app_log (LOG_SEV_INFO, "Nominated\n");
            else
                app_log (LOG_SEV_INFO, "NOT Nominated\n");
        }
    }

    return;
}



void app_media_misc_event_handler(handle h_inst, 
                    handle h_session, handle h_media, ice_misc_event_t event)
{
    switch (event)
    {
        case ICE_NEW_NOM_PAIR:

            app_log (LOG_SEV_INFO, 
                    "Nominated pair for a component of media has changed");
            break;

        default:
            break;
    }

    return;
}



void app_media_state_change_handler(handle h_inst, 
                            handle h_session, handle h_media, ice_state_t state)
{
    switch(state)
    {
        case ICE_GATHERED:
        case ICE_CC_RUNNING:
        case ICE_CC_FAILED:
        case ICE_CC_COMPLETED:
        {
            app_log (LOG_SEV_INFO, 
                    "************************************************************\n");
            app_log (LOG_SEV_INFO, 
                    "--- ICE session %p Media handle %p state changed to %s\n", 
                    h_session, h_media, states[state]);
            app_log (LOG_SEV_INFO, 
                    "************************************************************\n");
        }
        break;

        default: break;
    }

    return;
}


void app_session_state_change_handler(handle h_inst, 
                                    handle h_session, ice_state_t state)
{
    if ((state >= ICE_GATHERED) && (state <= ICE_CC_FAILED))
    {
        app_log (LOG_SEV_INFO, 
                "************************************************************\n");
        app_log (LOG_SEV_INFO, 
                "--- ICE session %p state changed to %s\n", h_session, states[state]);
        app_log (LOG_SEV_INFO, 
                "************************************************************\n");
    }

    switch(state)
    {
        case ICE_GATHERED:
            encode_session(h_inst, h_session);
            g_gather_done = true;
            break;
        case ICE_CC_FAILED: break;
        case ICE_CC_COMPLETED:
        {
            static int val = 1;
            if (val) {
                app_log (LOG_SEV_INFO, "\n\n\nICE negotiation completed, alert the local user\n");
                app_log (LOG_SEV_CRITICAL, " ----------------------------- SIP 180 RINGING -------------------------->\n");

                ice_lite_sample_print_valid_list(h_inst, h_session);

                encode_session(h_inst, h_session);
            }
            val=0;
            g_cc_done = true;
        }
        break;

        default:
            break;
    }

    return;
}



void app_parse_candidate_line(u_char *cand_line, ice_cand_params_t *cand)
{
    char protocol[10], typ[10], hosttype[10], rtag[10], rporttag[10];

    memset(cand, 0, sizeof(ice_cand_params_t));

    sscanf((char *)cand_line, "%s %d %s %lld %s %d %s %s %s %s %s %d", cand->foundation, 
            &cand->component_id, protocol, &cand->priority, 
            cand->ip_addr, &cand->port, typ, &hosttype[0], &rtag[0], 
            (char *)cand->rel_addr, rporttag, &cand->rel_port);

    if (!strcasecmp(protocol, "UDP")) { cand->protocol = ICE_TRANSPORT_UDP; }

    if (!strcasecmp(hosttype, "host"))
        cand->cand_type = ICE_CAND_TYPE_HOST;
    else if (!strcasecmp(hosttype, "srflx"))
        cand->cand_type = ICE_CAND_TYPE_SRFLX;
    else if (!strcasecmp(hosttype, "relay"))
        cand->cand_type = ICE_CAND_TYPE_RELAYED;
    else if (!strcasecmp(hosttype, "prflx"))
        cand->cand_type = ICE_CAND_TYPE_PRFLX;
    else 
        cand->cand_type = ICE_CAND_TYPE_INVALID;

    return;
}


void app_initialize_ice(void)
{
    int32_t status;
    ice_instance_callbacks_t app_cbs;
    ice_state_event_handlers_t event_hdlrs;

    status = ice_create_instance(&h_inst);
    if (status != STUN_OK)
    {
        app_log (LOG_SEV_ERROR, "ice_create_instance() returned error %d\n", status);
        return;
    }

    app_cbs.nwk_cb = app_nwk_send_msg;
    app_cbs.start_timer_cb = app_start_timer;
    app_cbs.stop_timer_cb = app_stop_timer;

    status = ice_instance_set_callbacks(h_inst, &app_cbs);
    if (status != STUN_OK)
    {
        app_log (LOG_SEV_ERROR, "ice_instance_set_callbacks() returned error %d\n", status);
        return;
    }

    event_hdlrs.session_state_cb = app_session_state_change_handler;
    event_hdlrs.media_state_cb = app_media_state_change_handler;
    event_hdlrs.misc_event_cb = app_media_misc_event_handler;

    status = ice_instance_register_event_handlers(h_inst, &event_hdlrs);
    if (status != STUN_OK)
    {
        app_log (LOG_SEV_ERROR, "ice_instance_register_event_handlers() returned error %d\n", status);
        return;
    }

    return;
}


int ice_lite_sample_create_host_candidate(int port)
{
    struct addrinfo req, *ans;
    int code, f;
    char service[16] = {0};

    snprintf(service, 16, "%d", port);

    /* 
     * Set ai_flags to AI_PASSIVE to indicate that return 
     * address is suitable for bind() 
     */
    req.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
#ifdef ICE_IPV6
    req.ai_family = PF_INET6;
#else
    req.ai_family = PF_INET;
#endif
    req.ai_socktype = SOCK_DGRAM;
    req.ai_protocol = 0;

    if ((code = getaddrinfo(NULL, service, &req, &ans)) != 0)
    {
        app_log(LOG_SEV_ERROR, "getaddrinfo failed code %d\n", code); 
        return 0;
    } 

    /* ans must contain at least one addrinfo, use the first. */
    f = socket(ans->ai_family, ans->ai_socktype, ans->ai_protocol);
    if (f < 0)
    {
        app_log (LOG_SEV_ERROR, "socket() failed\n");
        return 0;
    }

    if (bind(f, ans->ai_addr, ans->ai_addrlen) < 0)
    {
        app_log (LOG_SEV_ERROR, "bind() failed\n");
        return 0;
    }

    if (ans->ai_family == 10)
        app_log(LOG_SEV_DEBUG, "IP address mode: IPv6\n");
    else
        app_log(LOG_SEV_DEBUG, "IP address mode: IPv4\n");

    return f;
}


bool app_create_new_media(ice_api_media_stream_t *media, int32_t rtp_port, int32_t rtcp_port)
{
    int temp_sockfd;
    int32_t status;
    struct sockaddr_in local_addr;

    media->num_comp = 0;

    /** set the credentials for this media stream */
    strcpy(media->ice_ufrag, "ufrag");
    strcpy(media->ice_pwd, "pwd");

    /** adding rtp component */
    temp_sockfd = platform_create_socket(AF_INET, SOCK_DGRAM, 0);
    if (temp_sockfd == -1) return false;

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(rtp_port);
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    status = platform_bind_socket(temp_sockfd, 
            (struct sockaddr *)&local_addr, sizeof(local_addr));
    if (status == -1)
    {
        app_log (LOG_SEV_ERROR, 
                "binding to port failed... perhaps port already being used?\n");
        return false;
    }
    sockfd_ice[num_fds++] = temp_sockfd;

#ifdef ICE_IPV6
    media->host_cands[0].type = STUN_INET_ADDR_IPV6;
#else
    media->host_cands[0].type = STUN_INET_ADDR_IPV4;
#endif
    strcpy((char *)media->host_cands[0].ip_addr, LOCAL_IP);
    media->host_cands[0].port = rtp_port;
    media->host_cands[0].protocol = ICE_TRANSPORT_UDP;
    media->host_cands[0].comp_id = RTP_COMPONENT_ID;
    media->host_cands[0].transport_param = (handle)temp_sockfd;

    media->num_comp++;

    app_log(LOG_SEV_DEBUG, 
            "Transport param for component ID %d :-> %d", 
            media->host_cands[0].comp_id, temp_sockfd);

    if (rtcp_port == 0) return STUN_OK;

    /** adding rtcp component */
    temp_sockfd = platform_create_socket(AF_INET, SOCK_DGRAM, 0);
    if (temp_sockfd == -1) return false;

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(rtcp_port);
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    status = platform_bind_socket(temp_sockfd, 
                (struct sockaddr *) &local_addr, sizeof(local_addr));
    if (status == -1)
    {
        app_log (LOG_SEV_ERROR, 
                "binding to port failed... perhaps port already being used?");
        return false;
    }
    sockfd_ice[num_fds++] = temp_sockfd;

#ifdef ICE_IPV6
    media->host_cands[1].type = STUN_INET_ADDR_IPV6;
#else
    media->host_cands[1].type = STUN_INET_ADDR_IPV4;
#endif
    strcpy((char *)media->host_cands[1].ip_addr, LOCAL_IP);
    media->host_cands[1].port = rtcp_port;
    media->host_cands[1].protocol = ICE_TRANSPORT_UDP;
    media->host_cands[1].comp_id = RTCP_COMPONENT_ID;
    media->host_cands[1].transport_param = (handle)temp_sockfd;

    media->num_comp++;

    app_log(LOG_SEV_DEBUG, 
            "Transport param for component ID %d :-> %d", 
            media->host_cands[1].comp_id, temp_sockfd);

    return true;
}


int32_t get_user_choice(void)
{
    int32_t choice;

    printf ("\n\n\nWhat do you want to do today?\n");

    do
    {
        printf ("1. restart existing media\n");
        printf ("2. add new media\n");
        printf ("3. remove existing media\n");
        printf ("4. i am done\n");

        scanf("%d", &choice);
        
        if ((choice >= 1) && (choice <= 4))
        {
            printf ("You chose %d\n", choice);
            break;
        }

    } while(1);


    return choice;
}


void ice_lite_sample_restart_media(handle h_media)
{
    int32_t status;
    ice_media_credentials_t new_creds = {{0}, {0}};

    /**
     * an agent wishing to restart a media, should change the ice-pwd and
     * ice-ufrag for the media stream.
     */
    strncpy(new_creds.ice_ufrag, "restart_ufrag", ICE_MAX_UFRAG_LEN);
    strncpy(new_creds.ice_pwd, "restart_pwd", ICE_MAX_PWD_LEN);
    status = ice_session_set_media_credentials(h_inst, h_session, h_media, &new_creds);
    if (status != STUN_OK)
    {
        app_log (LOG_SEV_ERROR, 
                "ice_session_set_media_credentials() returned error %d\n",
                status);
        return;
    }

    status = ice_session_restart_media_stream(h_inst, h_session, h_media);
    if (status != STUN_OK)
    {
        app_log (LOG_SEV_ERROR, 
                "ice_session_restart_media_stream() returned error %d\n",
                status);
        return;
    }

    return;
}


handle ice_lite_sample_add_media(void)
{
    int32_t status;
    handle h_video;
    ice_api_media_stream_t new_media;

    memset(&new_media, 0, sizeof(ice_api_media_stream_t));

    /** prepare to add new media within a session - perhaps video? */
    app_create_new_media(&new_media, 
                LOCAL_VIDEO_ICE_RTP_PORT, LOCAL_VIDEO_ICE_RTCP_PORT);

    status = ice_session_add_media_stream(h_inst,
                                h_session, &new_media, &h_video);
    if (status != STUN_OK)
    {
        app_log (LOG_SEV_ERROR, 
                "ice_session_add_media_stream() returned error for "\
                "the new media %d\n", status);
        return NULL;
    }

    return h_video;
}


void ice_lite_sample_remove_media(void)
{
    int32_t status;
    handle h_media = NULL;
    ice_session_params_t session_desc;

    ice_session_get_session_params(h_inst, h_session, &session_desc);

    if (session_desc.num_media == 0)
    {
        printf ("There are no media stream to remove\n");
        return;
    }

    if (session_desc.num_media == 1)
    {
        printf ("There is only one media within the ice session\n");
        h_media = session_desc.media[0].h_media;
    }
    else
    {
        int32_t x, ch;

        printf ("Which media stream do you want to remove?\n\n");

        for (x = 0; x < session_desc.num_media; x++)
        {
            printf ("[%d]: %p\n", x+1, session_desc.media[x].h_media);
        }
        printf("\n\n");

        scanf("%d", &ch);

        h_media = session_desc.media[ch - 1].h_media;
        printf ("Removing media %p\n", h_media);
    }

    status = ice_session_remove_media_stream(h_inst, h_session, h_media);
    if (status != STUN_OK)
    {
        app_log (LOG_SEV_ERROR, 
                "ice_session_remove_media_stream() returned error %d\n", 
                status);
        return;
    }

    return;
}


int main (int argc, char *argv[])
{
    handle h_rcvdmsg, h_target, h_audio, h_video;
    int32_t status, ic_msg_count, choice;
    u_char address[16];
    unsigned int bytes, port;
    ice_api_media_stream_t media;
    ice_rx_stun_pkt_t pkt;

    h_audio = h_video = NULL;

    /** initialize platform library */
    platform_init();

    app_initialize_ice();

    status = ice_create_session(h_inst, ICE_SESSION_OUTGOING, &h_session);
    if (status != STUN_OK)
    {
        app_log (LOG_SEV_ERROR, "ice_create_session() returned error %d\n", status);
        return -1;
    }

    /** prepare to add new media - audio? */
    app_create_new_media(&media, LOCAL_AUDIO_ICE_RTP_PORT, LOCAL_AUDIO_ICE_RTCP_PORT);

    /** add media */
    status = ice_session_add_media_stream(h_inst, h_session, &media, &h_audio);
    if (status != STUN_OK)
    {
        app_log (LOG_SEV_ERROR, "ice_session_add_media_stream() returned error %d\n", status);
        return -1;
    }

    /** 
     * All the media streams of an ice lite session move into RUNNING 
     * state as soon as the media are added and are ready to respond 
     * to connectiity checks from remote.
     */

    encode_session(h_inst, h_session);

    app_log (LOG_SEV_ERROR, "**************************************************************\n");

    my_buf = (unsigned char *) platform_calloc (1, TRANSPORT_MTU_SIZE);

    ice_lite_input_remote_sdp(h_inst, h_session, h_audio);

    /**
     * Enable the following call to test scenarios where the peer is 
     * also a ice lite implementation and has provided multiple host
     * candidates (remember, IPv6 node can simultaneously have multiple
     * IPv6 addresses with different scopes. In such a scenario, the ice
     * stack will apply the rules as per rfc 3484 and nominate one of 
     * valid pairs.
     */
#ifdef ICE_TEST_RFC3484
    ice_lite_sample_print_valid_list(h_inst, h_session);

    /** 
     * if we are controlling agent, send out an offer with sdp attribute 
     * 'remote-candidates' set to the nominated pair among the available 
     * multiple valid pairs. Remember in this scenario, we have multiple
     * host candidates available for a component. 
     *
     * And wait for answer from the peer ...
     */

    /**
     * The answer from peer will hopefully contain a single candidate now
     * for every component and which matches the one in default media 
     * attribute. In which case, the ice session and media stream will
     * move to COMPLETED state.
     */
    ice_lite_input_remote_sdp(h_inst, h_session, h_audio);
#endif

    ic_msg_count = 0;

    while (g_cc_done == false) {

        int i, act_fd, fd_list[20];
        act_fd  = platform_socket_listen(sockfd_ice, num_fds, fd_list);

        app_log(LOG_SEV_DEBUG, "Select returned that there is activity on %d sockets", act_fd);

        for (i = 0; i < act_fd; i++)
        {
            bytes = platform_socket_recvfrom(fd_list[i], my_buf, TRANSPORT_MTU_SIZE, 0, address, &port);

            if (!bytes) continue;

            if (fd_list[i] == sockfd_sip)
            {
            }
            else
            {
                u_char log_buf[500];
                uint32_t log_buf_len = 500;

                printf ("COUNT: %d BYTES %d\n", ++ic_msg_count, bytes);
                status = stun_msg_decode(my_buf, bytes, true, &h_rcvdmsg);
                if (status != STUN_OK)
                {
                    app_log (LOG_SEV_ERROR, 
                            "stun_msg_decode() returned error %d\n", status);
                    continue;
                }

                stun_msg_print (h_rcvdmsg, log_buf, log_buf_len);
                app_log(LOG_SEV_INFO,
                        ">>>>>>>>>>\nRx STUN message from %s:%d\n\n%s\n\n<<<<<<<<<<\n\n", 
                        address, port, log_buf);

                status = ice_instance_find_session_for_received_msg(
                            h_inst, h_rcvdmsg, (handle) fd_list[i], &h_target);
                if (status == STUN_NOT_FOUND)
                {
                    app_log(LOG_SEV_ERROR, 
                            "No ICE session found for received message on "\
                            "transport fd %d", fd_list[i]);
                    app_log(LOG_SEV_ERROR, 
                            "Dropping the received message on transport fd %d",
                            fd_list[i]);
                    stun_msg_destroy(h_rcvdmsg);
                }
                else if (status == STUN_OK)
                {
                    pkt.h_msg = h_rcvdmsg;
                    pkt.transport_param = (handle) fd_list[i];
#ifdef ICE_IPV6
                    pkt.src.host_type = STUN_INET_ADDR_IPV6;
#else
                    pkt.src.host_type = STUN_INET_ADDR_IPV4;
#endif
                    strncpy((char *)pkt.src.ip_addr, (char *)address, 16);
                    pkt.src.port = port;

                    status = ice_session_inject_received_msg(h_inst, h_target, &pkt);
                    if (status != STUN_OK)
                    {
                        app_log (LOG_SEV_ERROR, "ice_session_inject_received_msg() returned error %d\n", status);
                        stun_msg_destroy(h_rcvdmsg);
                    }
                }
            }
        }
    }

    while (1)
    {
        /** what do you want to do next? */
        choice = get_user_choice();
        if (choice == 1)
        {
            ice_lite_sample_restart_media(h_audio);

            /** send offer to peer */
            encode_session(h_inst, h_session);
        }
        else if (choice == 2)
        {
            h_video = ice_lite_sample_add_media();

            /** send offer to peer */
            encode_session(h_inst, h_session);
        }
        else if (choice == 3)
        {
            ice_lite_sample_remove_media();

            encode_session(h_inst, h_session);
        }
        else
        {
            printf("Happy 'ice'ing\n");
            break;
        }
    }

    ice_destroy_session(h_inst, h_session);
    ice_destroy_instance(h_inst);
    platform_free(my_buf);

    platform_exit();

    return 0;
}


