

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <msg_layer_api.h>
#include <stun_tlv_api.h>
#include <stun_txn_api.h>
#include "ice_api.h"



//#define STUN_SRV_IP "198.65.166.165"
//#define STUN_SRV_IP "75.101.138.128"
//#define STUN_SRV_IP "216.146.46.55"
#define STUN_SRV_IP "127.0.0.1"
#define STUN_SRV_PORT 3478

#define TRANSPORT_MTU_SIZE  1500
#define AGENT1_USER_NAME "outgoing"
#define AGENT1_PASSWORD "password"
#define AGENT_DOMAIN "domain.org"

#define LOCAL_IP   "127.0.0.1"
#define LOCAL_ICE_RTP_HOST_PORT 44444
#define LOCAL_ICE_RTCP_HOST_PORT 44445
#define LOCAL_SIP_PORT 8888

#define PEER_SIP_IP "127.0.0.1"
#define PEER_SIP_PORT 8889

handle h_inst, h_session;
static int sockfd_sip = 0;
bool g_gather_done = false;
bool g_cc_done = false;
int sockfd_ice[3];
u_char *my_buf;

char *states[] =
{
    "ICE_IDLE",
    "ICE_GATHERING",
    "ICE_GATHERED",
    "ICE_CC_RUNNING",
    "ICE_CC_COMPLETED",
    "ICE_CC_FAILED",
    "ICE_NOMINATING",
    "ICE_ACTIVE",
};

void app_log(/** char *file_name, uint32_t line_num, */
                enum_stun_log_level level, char *format, ...)
{
    char buff[150];
    va_list args;
    va_start(args, format );
    //va_arg(args, file_name);
    //va_arg(args, line_num);
    sprintf(buff, "%s\n", format);
    vprintf(buff, args );
    va_end(args );
}

void app_timer_expiry_cb (void *timer_id, void *arg)
{
    handle h_txn;
    s_int32 status;

    app_log (LOG_SEV_DEBUG, "in sample application timer callback");

    /** inject timer message */
    //status = stun_txn_inject_timer_message(h_txn_inst, timer_id, arg, &h_txn);
    status = ice_session_inject_timer_event(timer_id, arg);
    if (status == STUN_TERMINATED)
    {
        /** destroy the transaction */
        app_log (LOG_SEV_INFO, "Destroying transaction %p\n", h_txn);
        //stun_destroy_txn(h_txn_inst, h_txn, false, false);
    }

    return;
}

s_int32 app_nwk_send_msg (handle h_msg, u_char *ip_addr, u_int32 port, handle param)
{
    int sent_bytes, buf_len, status;
    unsigned char *buf;
    int sock_fd = (int) param;

    buf = (u_char *) platform_malloc(TRANSPORT_MTU_SIZE);

    status = stun_msg_encode(h_msg, buf, (u_int32 *)&buf_len);
    if (status != STUN_OK)
        app_log (LOG_SEV_ERROR, "stun_msg_format() returned error %d\n", status);

    if (!sock_fd)
    {
        app_log (LOG_SEV_ERROR, "some error! transport socket handle is NULL\n");
    }

    sent_bytes = platform_socket_sendto(sock_fd, buf, 
                            buf_len, 0, AF_INET, port, ip_addr);
                            //buf_len, 0, AF_INET, STUN_SRV_PORT, STUN_SRV_IP);

    stun_free(buf);

    if (sent_bytes == -1)
        return STUN_INT_ERROR;
    else
        return STUN_OK;
}

handle app_start_timer (u_int32 duration, handle arg)
{
    timer_expiry_callback timer_cb = app_timer_expiry_cb;

    return platform_start_timer(duration, timer_cb, arg);
}

s_int32 app_stop_timer (handle timer_id)
{
    if (platform_stop_timer(timer_id) == true)
        return STUN_OK;
    else
        return STUN_NOT_FOUND;
}


s_int32 app_send_sdp_offer_to_peer(struct_gathered_list *local_cands)
{
    u_int32 i, j, k, sent_bytes, pos, temp = 0;
    s_char cand_line[150], *sip_buf;
    struct_gathered_media_stream *media;
    struct_gathered_media_comp *media_comp;

    sip_buf = (s_char *) platform_malloc(TRANSPORT_MTU_SIZE);

    app_log (LOG_SEV_CRITICAL, "\n\n");
    app_log (LOG_SEV_CRITICAL, "---------------------------INVITE--------------------------->\n\n");

    for (i = 0; i < local_cands->num_media; i++)
    {
        media = &local_cands->media[i];

        for (j = 0; j < media->num_comps; j++)
        {
            media_comp = &media->comps[j];

            app_log (LOG_SEV_CRITICAL, "COMPONENT ID : %d\n", media_comp->comp_id);

            for (k = 0; k < media_comp->num_cands; k++)
            {
                struct_gathered_candidate *cand = &media_comp->cands[k];
                stun_memset(cand_line, 0, 150);
                pos = 0;

                pos += sprintf (cand_line+pos, "a=%s %d", cand->foundation, 
                                                     cand->component_id);
                if (cand->protocol == ICE_TRANSPORT_UDP)
                    pos += sprintf (cand_line+pos, " UDP");
                else if (cand->protocol == ICE_TRANSPORT_TCP)
                    pos += sprintf (cand_line+pos, " TCP");

                pos += sprintf (cand_line+pos, " %d %s %d",  cand->priority, 
                                                    cand->ip_addr, cand->port);

                if (cand->cand_type == HOST_CANDIDATE)
                    pos += sprintf (cand_line+pos, " typ host"); 
                else if (cand->cand_type == SERVER_REFLEXIVE_CANDIDATE)
                    pos += sprintf (cand_line+pos, " typ srflx"); 
                else if (RELAYED_CANDIDATE == cand->cand_type)
                    pos += sprintf (cand_line+pos, " typ relay"); 
                else if (PEER_REFLEXIVE_CANDIDATE == cand->cand_type)
                    pos += sprintf (cand_line+pos, " typ prflx"); 
                else
                    app_log(LOG_SEV_ERROR, "Invalid ICE candidate type\n");

                pos += sprintf (cand_line+pos, " raddr %s rport %d\n", cand->rel_addr, cand->rel_port);

                app_log (LOG_SEV_DEBUG, "%s", cand_line);

                temp += sprintf(sip_buf+temp, cand_line);
            }
        }
    }

    sent_bytes = platform_socket_sendto(sockfd_sip, sip_buf, 
                            temp, 0, AF_INET, PEER_SIP_PORT, PEER_SIP_IP);
    app_log (LOG_SEV_CRITICAL, "Sent %d bytes to peer sip endpoint\n", sent_bytes);

    platform_free(sip_buf);

    return STUN_OK;
}

void app_session_state_change_handler(handle h_inst, 
        handle h_session, enum_ice_session_state state, handle param)
{
    app_log (LOG_SEV_INFO, "************************************************************\n");
    app_log (LOG_SEV_INFO, "--- state changed to %s\n", states[state]);
    app_log (LOG_SEV_INFO, "************************************************************\n");

    switch(state)
    {
        case ICE_IDLE: break;
        case ICE_GATHERING: break;
        case ICE_GATHERED:
            app_send_sdp_offer_to_peer((struct_gathered_list *) param);
            g_gather_done = true;
            break;
        case ICE_CC_RUNNING: break;
        case ICE_CC_COMPLETED: break;
        case ICE_CC_FAILED: break;
        case ICE_NOMINATING: break;
        case ICE_ACTIVE:
        {
            static int val = 1;
            if (val) {
            app_log (LOG_SEV_INFO, "\n\n\nICE negotiation completed, alert the local user\n");
            app_log (LOG_SEV_CRITICAL, " ----------------------------- SIP 180 RINGING -------------------------->\n");
            }
            val=0;
            g_cc_done = true;
        }
        break;
    }

    return;
}

void app_receive_data_from_peer(void)
{
    struct sockaddr_in sip_addr;

    if (!sockfd_sip)
    {
        sockfd_sip = platform_create_socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd_sip == -1) return;

        memset(&sip_addr, 0, sizeof(sip_addr));
        sip_addr.sin_family = AF_INET;
        sip_addr.sin_port = htons(LOCAL_SIP_PORT);
        sip_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        platform_bind_socket(sockfd_sip, &sip_addr, sizeof(sip_addr));
    }

    return;
}

void app_create_sip_socket(void)
{
    struct sockaddr_in sip_addr;

    if (!sockfd_sip)
    {
        sockfd_sip = platform_create_socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd_sip == -1) return;

        memset(&sip_addr, 0, sizeof(sip_addr));
        sip_addr.sin_family = AF_INET;
        sip_addr.sin_port = htons(LOCAL_SIP_PORT);
        sip_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        platform_bind_socket(sockfd_sip, &sip_addr, sizeof(sip_addr));
    }

    return;
}

void app_parse_candidate_line(u_char *cand_line, struct_gathered_candidate *cand)
{
    char protocol[10], typ[10], hosttype[10], rtag[10], rporttag[10];

    memset(cand, 0, sizeof(struct_gathered_candidate));

    sscanf(cand_line, "%s %d %s %lld %s %d %s %s %s %s %s %d", cand->foundation, 
            &cand->component_id, protocol, &cand->priority, 
            cand->ip_addr, &cand->port, typ, &hosttype[0], &rtag[0], 
            cand->rel_addr, rporttag, &cand->rel_port);

    if (!strcasecmp(protocol, "UDP")) { cand->protocol = ICE_TRANSPORT_UDP; }

    if (!strcasecmp(hosttype, "host"))
        cand->cand_type = HOST_CANDIDATE;
    else if (!strcasecmp(hosttype, "srflx"))
        cand->cand_type = SERVER_REFLEXIVE_CANDIDATE;
    else if (!strcasecmp(hosttype, "relay"))
        cand->cand_type = RELAYED_CANDIDATE;
    else if (!strcasecmp(hosttype, "prflx"))
        cand->cand_type = PEER_REFLEXIVE_CANDIDATE;
    else 
        cand->cand_type = INVALID_CAND_TYPE;

    return;
}


s_int32 app_parse_pseudo_sdp(u_char *parse_buf, 
                        u_int32 len, struct_gathered_list *remote_cands)
{
    u_char *start, *ptr;
    u_char cand_line[150];
    u_int32 i = 0;
    u_int32 comp1_count, comp2_count;
    struct_gathered_candidate cand;

    comp1_count = comp2_count = 0;

    /** here, we assume that there is only one media */
    remote_cands->num_media = 1;

    /** and always two components... */
    remote_cands->media[0].num_comps = 2;

    start = parse_buf;

    do
    {
        ptr = strchr(start, '\n');
        if (!ptr) break;
        memset(&cand_line, 0, 150);

        memcpy(&cand_line, start, (ptr-start));

        app_parse_candidate_line(cand_line, &cand);

        if (cand.component_id == RTP_COMPONENT_ID)
        {
            memcpy(&remote_cands->media[0].comps[cand.component_id-1].cands[comp1_count], &cand, sizeof(cand));
            comp1_count++;
        }
        else
        {
            memcpy(&remote_cands->media[0].comps[cand.component_id-1].cands[comp2_count], &cand, sizeof(cand));
            comp2_count++;
        }

        start = ptr+1; i++;
    } while (ptr != NULL);

    /** some more pre-defined values */
    remote_cands->media[0].comps[0].comp_id = RTP_COMPONENT_ID;
    remote_cands->media[0].comps[0].num_cands = comp1_count;

    remote_cands->media[0].comps[1].comp_id = RTCP_COMPONENT_ID;
    remote_cands->media[0].comps[1].num_cands = comp2_count;

    return STUN_OK;
}

void app_initialize_ice(void)
{
    struct_ice_instance_callbacks app_cbs;
    struct_ice_credentials cred;
    s_int32 status;

    status = ice_create_instance(&h_inst);
    if (status != STUN_OK)
        app_log (LOG_SEV_ERROR, "ice_create_instance() returned error %d\n", status);

    app_cbs.nwk_cb = app_nwk_send_msg;
    app_cbs.start_timer_cb = app_start_timer;
    app_cbs.stop_timer_cb = app_stop_timer;
    app_cbs.session_state_cb = app_session_state_change_handler;

    status = ice_instance_set_callbacks(h_inst, &app_cbs);
    if (status != STUN_OK)
        app_log (LOG_SEV_ERROR, "ice_instance_set_callbacks() returned error %d\n", status);


    status = ice_instance_set_turn_server(h_inst, STUN_SRV_IP, STUN_SRV_PORT);
    if (status != STUN_OK)
        app_log (LOG_SEV_ERROR, "ice_instance_set_turn_server() returned error %d\n", status);


    strncpy(cred.username, AGENT1_USER_NAME , TURN_MAX_USERNAME_LEN);
    strncpy(cred.password, AGENT1_PASSWORD, TURN_MAX_PASSWORD_LEN);
    strncpy(cred.realm, AGENT_DOMAIN, TURN_MAX_REALM_LEN);
    status = ice_instance_set_turn_credentials(h_inst, &cred);
    if (status != STUN_OK)
        app_log (LOG_SEV_ERROR, "ice_instance_set_turn_credentials() returned error %d\n", status);

    return;
}


int main (int argc, char *argv[])
{
    handle h_rcvdmsg, h_target;
    s_int32 status, loop;
    u_char address[16], port;
    int bytes, num_fds, rcvd_fd;
    struct_ice_api_media_stream media;
    struct sockaddr_in local_addr;
    struct_ice_api_media_stream remote_cands;
    struct_rx_stun_pkt pkt;

    /** initialize platform lib */
    platform_init();

    app_create_sip_socket();

    app_initialize_ice();

    status = ice_create_session(h_inst, ICE_SESSION_OUTGOING, ICE_FULL, &h_session);
    if (status != STUN_OK)
        app_log (LOG_SEV_ERROR, "ice_create_session() returned error %d\n", status);


    sockfd_ice[0] = platform_create_socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd_ice == -1) return STUN_INT_ERROR;

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(LOCAL_ICE_RTP_HOST_PORT);
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    status = platform_bind_socket(sockfd_ice[0], &local_addr, sizeof(local_addr));
    if (status == -1)
    {
        app_log (LOG_SEV_ERROR, "binding to port failed... perhaps port already being used?\n");
        return 0;
    }

    sockfd_ice[1] = platform_create_socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd_ice == -1) return STUN_INT_ERROR;

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(LOCAL_ICE_RTCP_HOST_PORT);
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    status = platform_bind_socket(sockfd_ice[1], &local_addr, sizeof(local_addr));
    if (status == -1)
    {
        app_log (LOG_SEV_ERROR, "binding to port failed... perhaps port already being used?\n");
        return 0;
    }

    num_fds = 2;

    media.num_comp = 2;

    media.host_cands[0].type = HOST_ADDR_IPV4;
    strcpy(media.host_cands[0].ip_addr, "127.0.0.1");
    media.host_cands[0].port = LOCAL_ICE_RTP_HOST_PORT;
    media.host_cands[0].protocol = ICE_TRANSPORT_UDP;
    media.host_cands[0].comp_id = RTP_COMPONENT_ID;
    media.host_cands[0].transport_param = sockfd_ice[0];

    app_log(LOG_SEV_DEBUG, 
            "Transport param for component ID %d :-> %d", 
            media.host_cands[0].comp_id, sockfd_ice[0]);

    media.host_cands[1].type = HOST_ADDR_IPV4;
    strcpy(media.host_cands[1].ip_addr, "127.0.0.1");
    media.host_cands[1].port = LOCAL_ICE_RTCP_HOST_PORT;
    media.host_cands[1].protocol = ICE_TRANSPORT_UDP;
    media.host_cands[1].comp_id = RTCP_COMPONENT_ID;
    media.host_cands[1].transport_param = sockfd_ice[1];

    app_log(LOG_SEV_DEBUG, 
            "Transport param for component ID %d :-> %d", 
            media.host_cands[1].comp_id, sockfd_ice[1]);

    status = ice_session_add_media_stream(h_inst, h_session, &media);
    if (status != STUN_OK)
        app_log (LOG_SEV_ERROR, "ice_session_add_media_stream() returned error %d\n", status);


    status = ice_session_gather_local_candidates(h_inst, h_session);
    if (status != STUN_OK)
        app_log (LOG_SEV_ERROR, "ice_session_gather_local_candidates() returned error %d\n", status);

    app_log (LOG_SEV_ERROR, "**************************************************************\n");

    my_buf = (unsigned char *) platform_malloc (TRANSPORT_MTU_SIZE);

    loop = 0;
    sockfd_ice[2] = sockfd_sip;
    num_fds++;

    while (g_gather_done == false) {

        int i, act_fd, fd_list[20];
        act_fd  = platform_socket_listen(sockfd_ice, num_fds, fd_list);

        app_log(LOG_SEV_DEBUG, "Select returned that there is activity on %d sockets", act_fd);

        for (i = 0; i < act_fd; i++)
        {
            bytes = platform_socket_recvfrom(fd_list[i], my_buf, TRANSPORT_MTU_SIZE, 0, address, &port);

            if (fd_list[i] == sockfd_sip)
            {
            }
            else
            {
                status = stun_msg_decode(my_buf, bytes, &h_rcvdmsg);
                if (status != STUN_OK)
                    app_log (LOG_SEV_ERROR, "stun_msg_decode() returned error %d\n", status);

                status = ice_instance_find_session_for_received_msg(h_inst, h_rcvdmsg, fd_list[i], &h_target);
                if (status == STUN_NOT_FOUND)
                {
                    /** TODO : create a new ice session and inject the message? */
                    app_log(LOG_SEV_ERROR, 
                            "No ICE session found for received message on transport fd %d", fd_list[i]);
                }
                else if (status == STUN_OK)
                {
                    pkt.h_msg = h_rcvdmsg;
                    pkt.transport_param = fd_list[i];
                    pkt.src.host_type = HOST_ADDR_IPV4;
                    strncpy(pkt.src.ip_addr, address, 16);
                    pkt.src.port = port;

                    status = ice_session_inject_received_msg(h_inst, h_target, &pkt);
                    loop++;
                }
            }
        }
    }

    printf ("[1]: buf => %p\n", my_buf);

    /** receive sdp answer */
    bytes = platform_socket_recvfrom(sockfd_sip, my_buf, TRANSPORT_MTU_SIZE, 0, address, &port);

    if (bytes < 0) { app_log (LOG_SEV_ERROR, "recvfrom failed\n"); }

    app_log (LOG_SEV_CRITICAL, "\n\n\n\n");
    app_log (LOG_SEV_CRITICAL, "<----------------------- 183 SESSION PROGRESS -------------------------");
    app_log (LOG_SEV_CRITICAL, "\n\nReceived answer from peer sip endpoint: %d bytes\n\n%s\n", bytes, my_buf);

    printf ("[2]: buf => %p\n", my_buf);

    app_parse_pseudo_sdp(my_buf, bytes, &remote_cands);

    printf ("[3]: buf => %p\n", my_buf);

    status = ice_session_set_remote_candidates(h_inst, h_session, &remote_cands);
    if (status != STUN_OK)
        app_log (LOG_SEV_ERROR, "ice_session_set_remote_candidates() returned error %d\n", status);

    status = ice_session_form_check_lists(h_inst, h_session);
    if (status != STUN_OK)
        app_log (LOG_SEV_ERROR, "ice_session_form_check_lists() returned error %d\n", status);

    status = ice_session_start_connectivity_checks(h_inst, h_session);
    if (status != STUN_OK)
        app_log (LOG_SEV_ERROR, "ice_session_start_connectivity_checks() returned error %d\n", status);

    num_fds = 3;

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
                status = stun_msg_decode(my_buf, bytes, &h_rcvdmsg);
                if (status != STUN_OK)
                    app_log (LOG_SEV_ERROR, "stun_msg_decode() returned error %d\n", status);

                status = ice_instance_find_session_for_received_msg(h_inst, h_rcvdmsg, fd_list[i], &h_target);
                if (status == STUN_NOT_FOUND)
                {
                    /** TODO : create a new ice session and inject the message? */
                    app_log(LOG_SEV_ERROR, 
                            "No ICE session found for received message on transport fd %d", fd_list[i]);
                }
                else if (status == STUN_OK)
                {
                    pkt.h_msg = h_rcvdmsg;
                    pkt.transport_param = fd_list[i];
                    pkt.src.host_type = HOST_ADDR_IPV4;
                    strncpy(pkt.src.ip_addr, address, 16);
                    pkt.src.port = port;

                    status = ice_session_inject_received_msg(h_inst, h_target, &pkt);
                    if (status != STUN_OK)
                        app_log (LOG_SEV_ERROR, "ice_session_inject_received_msg() returned error %d\n", status);
                }
            }
        }
    }


    ice_destroy_instance(h_inst);

    return 0;
}
