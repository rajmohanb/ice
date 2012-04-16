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


/*******************************************************************************
*                                                                              *
* This sample application shows how the ICE stack can be used to develop a     *
* ice agent application. The ice agent application shows the creation,         *
* deletion of ICE sessions in an interactive manner.                           *
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
#include <sys/time.h>
#include <msg_layer_api.h>
#include <stun_enc_dec_api.h>
#include <stun_txn_api.h>
#include "ice_api.h"


#ifdef ICE_IPV6
#define STUN_SRV_IP "2001:db8:0:242::67"
#define TURN_SRV_IP "2001:db8:0:242::67"
#else
#define STUN_SRV_IP "10.1.71.103"
//#define STUN_SRV_IP "192.168.1.2"
#define TURN_SRV_IP "10.1.71.101"
//#define TURN_SRV_IP "109.107.37.45"
#endif

#define STUN_SRV_PORT 3478
#define TURN_SRV_PORT 3478

#define TURN_USERNAME   "outgoing"
#define TURN_PASSWORD   "password"
#define TURN_DOMAIN     "domain.org"

#define TRANSPORT_MTU_SIZE  1500

#ifdef ICE_IPV6
#define LOCAL_IP   "2001:db8:0:242::67"
#else
#define LOCAL_IP   "172.16.8.101"
#endif

#define LOCAL_ICE_RTP_HOST_PORT  44444
#define LOCAL_ICE_RTCP_HOST_PORT 44445

#define DEMO_AGENT_TIMER_PORT    23456

#define ICE_VENDOR_NAME "MindBricks ICE agent v0.57"
#define ICE_VENDOR_NAME_LEN 25

#define APP_LOG(level, ...) app_log(level, __FILE__, __LINE__, ##__VA_ARGS__)


/*++++++++++++++++++++++++++++++++++++++++++++++*/
/** globals used by the test application */
static handle g_inst = NULL;
static handle g_session = NULL;
static handle g_audio = NULL;

bool g_demo_exit = false;
bool g_cc_done = false;

static int demo_sockfds[6] = {0};
static int demo_sockfds_count = 0;

u_char *demo_buf;

stun_log_level_t g_log_sev = LOG_SEV_DEBUG;

/*++++++++++++++++++++++++++++++++++++++++++++++*/

char *states[] =
{
    "ICE_GATHERED",
    "ICE_CC_RUNNING",
    "ICE_CC_COMPLETED",
    "ICE_CC_FAILED",
};

char *log_levels[] =
{
    "LOG_SEV_CRITICAL",
    "LOG_SEV_ERROR",
    "LOG_SEV_WARNING",
    "LOG_SEV_INFO",
    "LOG_SEV_DEBUG",
};


typedef struct
{
    void *timer_id;
    void *arg;
} ice_demo_timer_event_t;



void app_log(stun_log_level_t level,
        char *file_name, uint32_t line_num, char *format, ...)
{
    char buff[500];
    va_list args;
    int relative_time;
    static struct timeval init = { 0, 0 };
    struct timeval now;

    if (level > g_log_sev) return;

    if(init.tv_sec == 0 && init.tv_usec == 0)
        gettimeofday(&init, NULL);

    gettimeofday(&now, NULL);

    relative_time = 1000 * (now.tv_sec - init.tv_sec);
    if (now.tv_usec - init.tv_usec > 0)
        relative_time = relative_time + ((now.tv_usec - init.tv_usec) / 1000);
    else
        relative_time = relative_time - 1 + ((now.tv_usec - init.tv_usec) / 1000);


    va_start(args, format );
    sprintf(buff, "| %s | %i msec <%s: %i> %s\n", 
            log_levels[level], relative_time, file_name, line_num, format);
    vprintf(buff, args );
    va_end(args );
}


void app_timer_expiry_cb (void *timer_id, void *arg)
{
    static int32_t sock = 0;
    ice_demo_timer_event_t timer_event;

    APP_LOG (LOG_SEV_DEBUG,
            "[ICE_AGENT_DEMO] in sample application timer callback %d %p", timer_id, arg);

    if (sock == 0)
    {
        sock = platform_create_socket(AF_INET, SOCK_DGRAM, 0);
        if(sock == -1)
        {
            APP_LOG(LOG_SEV_CRITICAL, "[ICE AGENT DEMO] Timer event socket creation failed");
            return;
        }
    }

    timer_event.timer_id = timer_id;
    timer_event.arg = arg;

    platform_socket_sendto(sock, 
                (u_char *)&timer_event, sizeof(timer_event), 0, 
                AF_INET, DEMO_AGENT_TIMER_PORT, LOCAL_IP);
#if 0
    /** 
     * The following should be enabled only when the system timer 
     * callback calls the ICE timer API directly in the signal 
     * callback function. This is not advised as the signal 
     * handler must not take too much time and must return immediately.
     */

    /** inject timer message */
    status = ice_session_inject_timer_event(timer_id, arg);
    if (status == STUN_TERMINATED)
    {
        APP_LOG (LOG_SEV_INFO, "ice_session_inject_timer_event() returned failure");
    }
#endif

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
        APP_LOG (LOG_SEV_INFO,
                "[ICE AGENT DEMO] Invalid IP address family type. "\
                "Sending of STUN message failed");
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

void app_rx_data(handle h_inst, handle h_session, 
            handle h_media, uint32_t comp_id, void *data, uint32_t data_len)
{
    printf("Data returned for COMP ID: [%d] %s\n", comp_id, data);
    return;
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

    /* Write "dummy" SDP v=, o=, s=, and t= lines */
    printf("v=0\no=- 3414564553 3414923132 IN IP4 localhost\ns=ice\nt=0 0\n");

    ice_session_get_session_params(h_inst, h_session, &session_desc);

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



static void ice_input_remote_sdp(handle h_inst, handle h_session, handle h_media)
{
    char linebuf[80];
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
                APP_LOG(LOG_SEV_ERROR, "Error parsing media line");
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
                APP_LOG(LOG_SEV_ERROR, "Error parsing connection line");
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
            } else if (strcmp(attr, "rtcp")==0) {
                char *val = attr+strlen(attr)+1;
                int cnt;

                cnt = sscanf(val, "%d IN %s %s", &port, net, ip);
                if (cnt != 3) {
                    APP_LOG(LOG_SEV_ERROR, "Error parsing rtcp attribute");
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

                cand->protocol = STUN_INET_ADDR_IPV4;
                
                strcpy((char *)cand->ip_addr, ipaddr);
                cand->port = port;

            } else if (strcmp(attr, "ice-lite") == 0) {
                peer_session_desc.ice_mode = ICE_MODE_LITE;
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
        APP_LOG (LOG_SEV_ERROR,
                "ice_session_set_peer_session_params() returned error %d\n", 
                status);
    }

    printf ("Done, remote candidate(s) added\n");

on_error:
    return;
}


void ice_sample_print_valid_list(handle h_inst, handle h_session)
{
    int32_t status, i, j;
    ice_valid_pair_t *pair;
    ice_session_valid_pairs_t valid_list;
    ice_media_valid_pairs_t *valid_media;

    status = ice_session_get_nominated_pairs(h_inst, h_session, &valid_list);
    if (status != STUN_OK)
    {
        APP_LOG (LOG_SEV_ERROR,
                "Unable to get the valid list for media\n");
        return;
    }

    APP_LOG (LOG_SEV_INFO, "Number of media %d\n", valid_list.num_media);
    for (i = 0; i < valid_list.num_media; i++)
    {
        valid_media = &valid_list.media_list[i];

        APP_LOG (LOG_SEV_INFO,
                "Number of Nominated pairs %d\n", valid_media->num_valid);
        APP_LOG (LOG_SEV_INFO, "NOMINATED LIST\n");

        for (j = 0; j < valid_media->num_valid; j++)
        {
            pair = &valid_media->pairs[j];
            APP_LOG (LOG_SEV_INFO,
                    "comp id: %d local: %s:%d peer: %s:%d", 
                    pair->comp_id, pair->local.ip_addr, pair->local.port,
                    pair->peer.ip_addr, pair->peer.port);
        }
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
            APP_LOG (LOG_SEV_INFO,
                    "************************************************************\n");
            APP_LOG (LOG_SEV_INFO,
                    "--- ICE session %p Media handle %p state changed to %s\n", 
                    h_session, h_media, states[state]);
            APP_LOG (LOG_SEV_INFO,
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
    uint32_t status;

    if ((state >= ICE_GATHERED) && (state <= ICE_CC_FAILED))
    {
        APP_LOG (LOG_SEV_INFO,
                "************************************************************\n");
        APP_LOG (LOG_SEV_INFO,
                "--- ICE session %p state changed to %s\n", h_session, states[state]);
        APP_LOG (LOG_SEV_INFO,
                "************************************************************\n");
    }

    switch(state)
    {
        case ICE_GATHERED:
        
            APP_LOG (LOG_SEV_INFO,
                    "ICE candidates gathering completed successfully");
            //encode_session(h_inst, h_session);
            break;

        case ICE_CC_RUNNING:
            break;

        case ICE_CC_COMPLETED:
        {
            static int val = 1;
            if (val) {
                APP_LOG (LOG_SEV_INFO,
                        "\n\n\nICE negotiation completed, alert the local user\n");
                APP_LOG (LOG_SEV_CRITICAL,
                        " ----------------------------- SIP 180 RINGING -------------------------->\n");

                ice_sample_print_valid_list(h_inst, h_session);

                encode_session(h_inst, h_session);
            }
            val=0;
            g_cc_done = true;
        }
        break;

        case ICE_CC_FAILED:
        {
            APP_LOG (LOG_SEV_INFO, "ICE session failed, destroying session");

            status = ice_destroy_session(h_inst, h_session);
            if(status != STUN_OK)
            {
                APP_LOG (LOG_SEV_ERROR, "Destroying of ICE session failed %d", status);
            }
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


void app_create_ice_instance(void)
{
    int32_t status;
    ice_instance_callbacks_t app_cbs;
    ice_state_event_handlers_t event_hdlrs;

    if (g_inst != NULL)
    {
        APP_LOG (LOG_SEV_ERROR, "ICE instance exists");
        return;
    }

    status = ice_create_instance(&g_inst);
    if (status != STUN_OK)
    {
        APP_LOG (LOG_SEV_ERROR,
                "ice_create_instance() returned error %d\n", status);
        g_inst = NULL;
        return;
    }

    app_cbs.nwk_cb = app_nwk_send_msg;
    app_cbs.start_timer_cb = app_start_timer;
    app_cbs.stop_timer_cb = app_stop_timer;
    app_cbs.app_data_cb = app_rx_data;

    status = ice_instance_set_callbacks(g_inst, &app_cbs);
    if (status != STUN_OK)
    {
        APP_LOG (LOG_SEV_ERROR,
                "ice_instance_set_callbacks() returned error %d\n", status);
        goto ERROR_EXIT;
    }

    event_hdlrs.session_state_cb = app_session_state_change_handler;
    event_hdlrs.media_state_cb = app_media_state_change_handler;

    status = ice_instance_register_event_handlers(g_inst, &event_hdlrs);
    if (status != STUN_OK)
    {
        APP_LOG (LOG_SEV_ERROR,
                "ice_instance_register_event_handlers() returned error %d\n",
                status);
        goto ERROR_EXIT;
    }

    status = ice_instance_set_client_software_name(g_inst, 
                            (u_char *)ICE_VENDOR_NAME, ICE_VENDOR_NAME_LEN);
    if (status != STUN_OK)
    {
        APP_LOG (LOG_SEV_ERROR,
                "Setting of ICE agent vendor name failed,"\
                " returned error %d\n", status);
        goto ERROR_EXIT;
    }

    status = ice_instance_set_connectivity_check_nomination_mode(
                                        g_inst, ICE_NOMINATION_TYPE_REGULAR);

    APP_LOG (LOG_SEV_INFO, "ICE instance created successfully");
    return;

ERROR_EXIT:
    ice_destroy_instance(g_inst);
    g_inst = NULL;
    return;
}


void app_create_ice_session(void)
{
    char choice[4];
    int32_t ch, status;
    ice_mode_type_t ses_mode;
    ice_session_type_t ses_type;
    ice_relay_server_cfg_t turn_cfg;
    ice_stun_server_cfg_t stun_cfg;

    if (g_session != NULL)
    {
        APP_LOG (LOG_SEV_ERROR, "ICE session exists");
        return;
    }

    do
    {
        puts("+-------------------------+");
        puts("| 1. Outgoing session     |");
        puts("| 2. Incoming session     |");
        puts("+-------------------------+");

        puts("Please inout choice");
        fgets(choice, sizeof(choice), stdin);

        ch = atoi(choice);
    } while ((ch < 1) && (ch > 2));

    if (ch == 1)
        ses_type = ICE_SESSION_OUTGOING;
    else
        ses_type = ICE_SESSION_INCOMING;

    ses_mode = ICE_MODE_FULL;

    status = ice_create_session(g_inst, ses_type, ses_mode, &g_session);
    if (status != STUN_OK)
    {
        APP_LOG(LOG_SEV_ERROR,
                "ICE session creation failed - %d", status);
        g_session = NULL;
    }

    turn_cfg.server.host_type = STUN_INET_ADDR_IPV4;
    stun_strncpy((char *)&turn_cfg.server.ip_addr, TURN_SRV_IP, ICE_IP_ADDR_MAX_LEN - 1);
    turn_cfg.server.port = TURN_SRV_PORT; 

    stun_strncpy((char *)&turn_cfg.username, TURN_USERNAME, TURN_MAX_USERNAME_LEN - 1);
    stun_strncpy((char *)&turn_cfg.credential, TURN_PASSWORD, TURN_MAX_PASSWORD_LEN - 1);
    stun_strncpy((char *)&turn_cfg.realm, TURN_DOMAIN, TURN_MAX_REALM_LEN - 1);

    status = ice_session_set_relay_server_cfg(g_inst, g_session, &turn_cfg);
    if (status != STUN_OK)
    {
        APP_LOG (LOG_SEV_ERROR,
                "ice_session_set_relay_server_cfg() returned error %d\n", status);
        return;
    }


    stun_cfg.server.host_type = STUN_INET_ADDR_IPV4;
    stun_strncpy((char *)&stun_cfg.server.ip_addr, STUN_SRV_IP, ICE_IP_ADDR_MAX_LEN - 1);
    stun_cfg.server.port = STUN_SRV_PORT; 

    status = ice_session_set_stun_server_cfg(g_inst, g_session, &stun_cfg);
    if (status != STUN_OK)
    {
        APP_LOG (LOG_SEV_ERROR,
                "ice_session_set_stun_server_cfg() returned error %d\n", status);
        return;
    }

    APP_LOG (LOG_SEV_INFO, "ICE session created successfully");
    return;
}


void app_add_media(void)
{
    int32_t status;
    struct sockaddr_in local_addr;
    ice_api_media_stream_t media;

    if (g_audio != NULL)
    {
        APP_LOG (LOG_SEV_ERROR, "ICE media exists");
        return;
    }

    memset(&media, 0, sizeof(media));

    demo_sockfds[2] = platform_create_socket(AF_INET, SOCK_DGRAM, 0);
    if (demo_sockfds[2] == -1) return;
    demo_sockfds_count++;

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(LOCAL_ICE_RTP_HOST_PORT);
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    status = platform_bind_socket(demo_sockfds[2], 
            (struct sockaddr *)&local_addr, sizeof(local_addr));
    if (status == -1)
    {
        APP_LOG (LOG_SEV_ERROR,
                "binding to port failed... perhaps port already being used?\n");
        return;
    }

    demo_sockfds[3] = platform_create_socket(AF_INET, SOCK_DGRAM, 0);
    if (demo_sockfds[3] == -1) return;
    demo_sockfds_count++;

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(LOCAL_ICE_RTCP_HOST_PORT);
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    status = platform_bind_socket(demo_sockfds[3], 
                (struct sockaddr *) &local_addr, sizeof(local_addr));
    if (status == -1)
    {
        APP_LOG (LOG_SEV_ERROR,
                "binding to port failed... perhaps port already being used?\n");
        return;
    }

    media.num_comp = 2;

#ifdef ICE_IPV6
    media.host_cands[0].addr.host_type = STUN_INET_ADDR_IPV6;
#else
    media.host_cands[0].addr.host_type = STUN_INET_ADDR_IPV4;
#endif
    strcpy((char *)media.host_cands[0].addr.ip_addr, LOCAL_IP);
    media.host_cands[0].addr.port = LOCAL_ICE_RTP_HOST_PORT;
    media.host_cands[0].protocol = ICE_TRANSPORT_UDP;
    media.host_cands[0].comp_id = RTP_COMPONENT_ID;
    media.host_cands[0].transport_param = (handle)demo_sockfds[2];
    media.host_cands[0].local_pref = LOCAL_PREF_IPV4;

    APP_LOG(LOG_SEV_DEBUG,
            "Transport param for component ID %d :-> %d", 
            media.host_cands[0].comp_id, demo_sockfds[2]);

#ifdef ICE_IPV6
    media.host_cands[1].addr.host_type = STUN_INET_ADDR_IPV6;
#else
    media.host_cands[1].addr.host_type = STUN_INET_ADDR_IPV4;
#endif
    strcpy((char *)media.host_cands[1].addr.ip_addr, LOCAL_IP);
    media.host_cands[1].addr.port = LOCAL_ICE_RTCP_HOST_PORT;
    media.host_cands[1].protocol = ICE_TRANSPORT_UDP;
    media.host_cands[1].comp_id = RTCP_COMPONENT_ID;
    media.host_cands[1].transport_param = (handle)demo_sockfds[3];
    media.host_cands[1].local_pref = LOCAL_PREF_IPV4;

    APP_LOG(LOG_SEV_DEBUG,
            "Transport param for component ID %d :-> %d", 
            media.host_cands[1].comp_id, demo_sockfds[3]);


    /** set the credentials for this media stream */
    strcpy(media.ice_ufrag, "ufrag");
    strcpy(media.ice_pwd, "pwd");


    status = ice_session_add_media_stream(g_inst, g_session, &media, &g_audio);
    if (status != STUN_OK)
    {
        APP_LOG (LOG_SEV_ERROR,
                "ice_session_add_media_stream() returned error %d", status);
        return;
    }

    APP_LOG (LOG_SEV_INFO,
            "Adding of media to session succeeded");

    return;
}


void app_gather_ice_candidates(void)
{
    int32_t status = ice_session_gather_candidates(g_inst, g_session, false);

    if (status != STUN_OK)
    {
        APP_LOG(LOG_SEV_ERROR,
                "Gathering of ICE candidates failed - %d", status);
        return;
    }

    APP_LOG(LOG_SEV_INFO, "Gathering of ICE candidates started");

    return;
}


void app_display_local_ice_description(void)
{
    encode_session(g_inst, g_session);
}


void app_input_remote_ice_description(void)
{
    ice_input_remote_sdp(g_inst, g_session, g_audio);
}


void app_start_connectivity_checks(void)
{
    int32_t status;

    APP_LOG (LOG_SEV_ERROR, "Forming connectivity check lists ...\n");
    status = ice_session_form_check_lists(g_inst, g_session);
    if (status != STUN_OK)
    {
        APP_LOG (LOG_SEV_ERROR,
                "ice_session_form_check_lists() returned error %d\n", status);
        return;
    }

    APP_LOG (LOG_SEV_ERROR, "Starting ICE connectivity checks ...\n");
    status = ice_session_start_connectivity_checks(g_inst, g_session);
    if (status != STUN_OK)
    {
        APP_LOG (LOG_SEV_ERROR,
                "ice_session_start_connectivity_checks() returned error %d\n", 
                status);
        return;
    }

    return;
}


void app_print_nominated_pair(void)
{
    ice_sample_print_valid_list(g_inst, g_session);
}


void app_send_rtp_data(void)
{
    int32_t status;
    char data[80];

    if (stdout) fflush(stdout);
    if (stdin) fflush(stdin);

    fgets(data, sizeof(data), stdin);
    
    status = ice_session_send_media_data(g_inst, g_session, 
            g_audio, RTP_COMPONENT_ID, (u_char *)data, strlen(data));
    if (status != STUN_OK)
    {
        APP_LOG (LOG_SEV_ERROR,
                "Sending of RTP media data failed with status %d\n", status);
    }

    return;
}



void app_send_rtcp_data(void)
{
    int32_t status;
    char data[80];

    if (stdout) fflush(stdout);
    if (stdin) fflush(stdin);

    fgets(data, sizeof(data), stdin);
    
    status = ice_session_send_media_data(g_inst, g_session, 
                g_audio, RTCP_COMPONENT_ID, (u_char *)data, strlen(data));
    if (status != STUN_OK)
    {
        APP_LOG (LOG_SEV_ERROR,
                "Sending of RTCP media data failed with status %d\n", status);
    }

    return;
}


void app_remove_media(void)
{
    int32_t status = ice_session_remove_media_stream(g_inst, g_session, g_audio);
    if(status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR,
                "Removing of media from the ICE session failed - %d", status);
        return;
    }

    ICE_LOG(LOG_SEV_ERROR, "Removing of media initiated");

    g_audio = NULL;
    return;
}


void app_destroy_ice_session(void)
{
    int32_t status = ice_destroy_session(g_inst, g_session);
    if(status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR,
                "Destroying of ICE session failed - %d", status);
        return;
    }

    g_session = NULL;

    /** 
     * do'nt set the g_session to NULL. When destroy 
     * completes, the app will be notified via callback 
     */

    ICE_LOG(LOG_SEV_ERROR, "Destroying of ICE session initiated");

    return;
}


void app_destroy_ice_instance(void)
{
    int32_t status = ice_destroy_instance(g_inst);
    if(status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR,
                "Destroying of ICE instance failed - %d", status);
        return;
    }

    g_inst = NULL;
    ICE_LOG(LOG_SEV_ERROR, "Destroying of ICE instance succeeded");

    return;

}


int ice_lite_sample_create_host_candidate(int port)
{
#ifdef ICE_IPV6
    struct sockaddr_in6 from;
    int len;
#endif
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
        APP_LOG(LOG_SEV_ERROR, "getaddrinfo failed code %d\n", code); 
        return 0;
    } 

    /* ans must contain at least one addrinfo, use the first. */
    f = socket(ans->ai_family, ans->ai_socktype, ans->ai_protocol);
    if (f < 0)
    {
        APP_LOG (LOG_SEV_ERROR, "socket() failed\n");
        return 0;
    }

    if (bind(f, ans->ai_addr, ans->ai_addrlen) < 0)
    {
        APP_LOG (LOG_SEV_ERROR, "bind() failed\n");
        return 0;
    }

    if (ans->ai_family == 10)
        APP_LOG(LOG_SEV_DEBUG, "IP address mode: IPv6\n");
    else
        APP_LOG(LOG_SEV_DEBUG, "IP address mode: IPv4\n");

    return f;
}


void ice_agent_demo_menu(void)
{
    puts("+----------------------------------------------------------------+");
    puts("|                            MENU                                |");
    puts("+----------------------------------------------------------------+");
    puts("|  1 | create ICE instance                                       |");
    puts("|  2 | create ICE session - controlling/controlled               |");
    puts("|  3 | add media                                                 |");
    puts("|  4 | gather candidates                                         |");
    puts("|  5 | display local ICE description                             |");
    puts("|  6 | set remote ICE information                                |");
    puts("|  7 | begin ICE negotiation                                     |");
    puts("|  8 | get nominated pair                                        |");
    puts("|  9 | Send RTP media                                            |");
    puts("| 10 | Send RTCP media                                           |");
    puts("| 11 | remove media                                              |");
    puts("| 12 | destroy ICE session                                       |");
    puts("| 13 | destroy ICE instance                                      |");
    puts("+----------------------------------------------------------------+");
    puts("| 0 | quit                                                       |");
    puts("+----------------------------------------------------------------+");
}


int32_t ice_agent_demo_init(void)
{
    int32_t status;
    struct sockaddr_in local_addr;

    /**
     * Allocate memory for the buffer which will be used for receiving the
     * data over the network. Once the message is received, it is passed
     * on to the ICE stack.
     */
    demo_buf = (unsigned char *) platform_calloc (1, TRANSPORT_MTU_SIZE);
    if (demo_buf == NULL)
    {
        puts("Memory allocation failed for demo appliation");
        return -1;
    }

    /** Add stdin */
    demo_sockfds[0] = STDIN_FILENO;
    demo_sockfds_count++;

    /** 
     * create unix domain socket used by the timer thread 
     * to communicate timer expiry to the main thread.
     */
    demo_sockfds[1] = platform_create_socket(AF_INET, SOCK_DGRAM, 0);
    if (demo_sockfds[1] == -1) return -1;

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(DEMO_AGENT_TIMER_PORT);
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    status = platform_bind_socket(demo_sockfds[1], 
            (struct sockaddr *)&local_addr, sizeof(local_addr));
    if (status == -1)
    {
        APP_LOG (LOG_SEV_ERROR,
                "binding to port failed... perhaps port already being used?\n");
        return status;
    }
    demo_sockfds_count++;
    
    return 0;
}


void ice_agent_handle_user_choice(char *choice)
{
    int ch = atoi(choice);

    if ((ch == 0) && (*choice == 48))
    {
        g_demo_exit = true;
    }
    else if (ch == 1)
    {
        app_create_ice_instance();
    }
    else if (ch == 2)
    {
        app_create_ice_session();
    }
    else if (ch == 3)
    {
        app_add_media();
    }
    else if (ch == 4)
    {
        app_gather_ice_candidates();
    }
    else if (ch == 5)
    {
        app_display_local_ice_description();
    }
    else if (ch == 6)
    {
        app_input_remote_ice_description();
    }
    else if (ch == 7)
    {
        app_start_connectivity_checks();
    }
    else if (ch == 8)
    {
        app_print_nominated_pair();
    }
    else if (ch == 9)
    {
        app_send_rtp_data();
    }
    else if (ch == 9)
    {
        app_send_rtcp_data();
    }
    else if (ch == 11)
    {
        app_remove_media();
    }
    else if (ch == 12)
    {
        app_destroy_ice_session();
    }
    else if (ch == 13)
    {
        app_destroy_ice_instance();
    }

    return;
}


void ice_agent_handle_timer_event(ice_demo_timer_event_t *event, uint32_t bytes)
{
    int32_t status;
    handle ice_session;

    if (g_inst == NULL) return;

    /** inject timer message */
    status = ice_session_inject_timer_event(
                        event->timer_id, event->arg, &ice_session);
    if (status == STUN_TERMINATED)
    {
        APP_LOG (LOG_SEV_INFO,
                "ice_session_inject_timer_event() returned failure. "\
                "The ICE session has terminated due to timeout");
        g_demo_exit = true;
    }

    return;
}


int main (int argc, char *argv[])
{
    handle h_rcvdmsg, h_target;
    int32_t status;
    u_char address[16];
    unsigned int bytes, port;
    ice_rx_stun_pkt_t pkt;
    int i, act_fd, fd_list[20];


    /** initialize platform library */
    platform_init();
    if (ice_agent_demo_init() < 0)
    {
        APP_LOG(LOG_SEV_ERROR,
                "Demo initialization failed... aborting");
        return -1;
    }

    while (g_demo_exit == false)
    {
        ice_agent_demo_menu();

        act_fd = platform_socket_listen(demo_sockfds, 
                                                demo_sockfds_count, fd_list);

        for (i = 0; i < act_fd; i++)
        {
            bytes = platform_socket_recvfrom(fd_list[i], 
                            demo_buf, TRANSPORT_MTU_SIZE, 0, address, &port);
            if (!bytes) continue;

            if (fd_list[i] == demo_sockfds[0])
            {
                char choice[4];

                if (stdout) fflush(stdout);
                if (stdin) fflush(stdin);

                fgets(choice, sizeof(choice), stdin);

                ice_agent_handle_user_choice(choice);
            }
            else if (fd_list[i] == demo_sockfds[1])
            {
                ice_agent_handle_timer_event(
                        (ice_demo_timer_event_t *)demo_buf, bytes);
            }
            else
            {
                /** check if stun message */
                status = ice_instance_verify_valid_stun_packet(demo_buf, bytes);
                if (status == STUN_MSG_NOT) continue;

                status = stun_msg_decode(demo_buf, bytes, false, &h_rcvdmsg);
                if (status != STUN_OK)
                {
                    APP_LOG (LOG_SEV_ERROR,
                            "stun_msg_decode() returned error %d\n", status);
                    continue;
                }

                stun_msg_print (h_rcvdmsg, demo_buf, TRANSPORT_MTU_SIZE);
                APP_LOG(LOG_SEV_INFO,
                        ">>>>>>>>>>\nRx STUN message from %s:%d\n\n%s\n\n<<<<<<<<<<\n\n", 
                        address, port, demo_buf);

                status = ice_instance_find_session_for_received_msg(
                            g_inst, h_rcvdmsg, (handle) fd_list[i], &h_target);
                if (status == STUN_NOT_FOUND)
                {
                    APP_LOG(LOG_SEV_ERROR,
                            "No ICE session found for received message on "\
                            "transport fd %d", fd_list[i]);
                    APP_LOG(LOG_SEV_ERROR,
                            "Dropping the received message on transport fd %d",
                            fd_list[i]);
                    stun_msg_destroy(h_rcvdmsg);
                }
                else if (status == STUN_OK)
                {
                    pkt.h_msg = h_rcvdmsg;
                    pkt.transport_param = (handle) fd_list[i];
                    pkt.src.host_type = STUN_INET_ADDR_IPV4;
                    strncpy((char *)pkt.src.ip_addr, (char *)address, 16);
                    pkt.src.port = port;

                    status = ice_session_inject_received_msg(
                                                        g_inst, h_target, &pkt);
                    if (status != STUN_OK)
                    {
                        APP_LOG (LOG_SEV_ERROR,
                                "ice_session_inject_received_msg() "\
                                "returned error %d\n", status);
                        if (status == STUN_INVALID_PARAMS) 
                            stun_msg_destroy(h_rcvdmsg);
                    }
                }
            }
        }
    }

    ice_destroy_session(g_inst, g_session);
    ice_destroy_instance(g_inst);
    platform_free(demo_buf);

    platform_exit();

    return 0;
}


