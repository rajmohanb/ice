
#define ENABLE_TURN

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <msg_layer_api.h>
#include <stun_tlv_api.h>
#include <stun_txn_api.h>
#include "conn_check_api.h"



//#define STUN_SRV_IP "198.65.166.165"
//#define STUN_SRV_IP "75.101.138.128"
//#define STUN_SRV_IP "216.146.46.55"
#define STUN_SRV_IP   "127.0.0.1"
#define STUN_SRV_PORT 6969

#define TRANSPORT_MTU_SIZE  1500
#define TEST_USER_NAME "toto"
//#define TEST_USER_NAME "rajmohanb@yahoo.com"

#define LOCAL_CONN_CHECK_PORT 6868

handle h_inst, h_session;

char *states[] = 
{
    "CC_OG_IDLE",
    "CC_OG_CHECKING",
    "CC_OG_INPROGRESS",
    "CC_OG_TERMINATED",
    "CC_IC_IDLE",
    "CC_IC_CHALLENGED",
    "CC_IC_TERMINATED",
};


void app_timer_expiry_cb (void *timer_id, void *arg)
{
#if 0
    handle h_txn;
    s_int32 status;

    /** inject timer message */
    status = stun_txn_inject_timer_message(h_txn_inst, timer_id, arg, &h_txn);
    if (status == STUN_TERMINATED)
    {
        /** destroy the transaction */
        printf ("Destroying transaction %p\n", h_txn);
        stun_destroy_txn(h_txn_inst, h_txn, false, false);
    }
#endif

    return;
}

s_int32 app_nwk_send_msg (handle h_msg, handle param)
{
    int sent_bytes, buf_len, sockfd_cc, status;
    unsigned char *buf;

    buf = (u_char *) platform_malloc(TRANSPORT_MTU_SIZE);

    status = stun_msg_encode(h_msg, buf, (u_int32 *)&buf_len);
    if (status != STUN_OK)
        printf ("stun_msg_format() returned error %d\n", status);
    else
        printf ("stun_msg_format() succeeded\n");

    sockfd_cc = (int) param;

    sent_bytes = platform_socket_sendto(sockfd_cc, buf, 
                            buf_len, 0, AF_INET, STUN_SRV_PORT, STUN_SRV_IP);

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

void app_session_state_change_handler(handle h_inst, 
        handle h_session, enum_conn_check_session_state state, handle param)
{
    struct_conn_check_result *cc_status = (struct_conn_check_result *) param;

    printf ("************************************************************\n");
    printf ("--- state changed to %s\n", states[state]);
    printf ("************************************************************\n");

    switch(state)
    {
        case CC_OG_TERMINATED:
        case CC_IC_TERMINATED:
            if (cc_status->cc_succeeded == true)
                printf ("Connectivity check succeeded\n");
            else 
                printf ("Connectivity check failed\n");
            break;

        default:
            break;
    }

    return;
}


int main (int argc, char *argv[])
{
    handle h_rcvdmsg;
    s_int32 status;
    u_char *buf, address[16], port;
    int bytes, sockfd_cc;
    struct_conn_check_instance_callbacks app_cbs;
    struct_conn_check_credentials cred;
    struct sockaddr_in local_addr;

    /** initialize platform lib */
    platform_init();

    sockfd_cc = platform_create_socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd_cc == -1) return STUN_INT_ERROR;

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(LOCAL_CONN_CHECK_PORT);
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    status = platform_bind_socket(sockfd_cc, &local_addr, sizeof(local_addr));
    if (status == -1)
    {
        printf ("binding to port failed... perhaps port already being used?\n");
        return 0;
    }

    status = conn_check_create_instance(&h_inst);
    if (status != STUN_OK)
        printf ("conn_check_create_instance() returned error %d\n", status);
    else
        printf ("conn_check_create_instance() succeeded\n");

    app_cbs.nwk_cb = app_nwk_send_msg;
    app_cbs.start_timer_cb = app_start_timer;
    app_cbs.stop_timer_cb = app_stop_timer;
    app_cbs.session_state_cb = app_session_state_change_handler;

    status = conn_check_instance_set_callbacks(h_inst, &app_cbs);
    if (status != STUN_OK)
        printf ("conn_check_instance_set_callbacks() returned error %d\n", status);
    else
        printf ("conn_check_instance_set_callbacks() succeeded\n");

    status = conn_check_create_session(h_inst, CC_CLIENT_SESSION, &h_session);
    if (status != STUN_OK)
        printf ("conn_check_create_session() returned error %d\n", status);
    else
        printf ("conn_check_create_session() succeeded\n");

    strncpy(cred.username, TEST_USER_NAME, STUN_MAX_USERNAME_LEN);
    strncpy(cred.password, "toto", STUN_MAX_PASSWORD_LEN);
    strncpy(cred.realm, "domain.org", STUN_MAX_REALM_LEN);
    status = conn_check_session_set_credentials(h_inst, h_session, &cred);
    if (status != STUN_OK)
        printf ("conn_check_session_set_credentials() returned error %d\n", status);
    else
        printf ("conn_check_session_set_credentials() succeeded\n");

    status = conn_check_session_set_transport_param(h_inst, h_session, sockfd_cc);
    if (status != STUN_OK)
        printf ("conn_check_session_set_transport_param() returned error %d\n", status);
    else
        printf ("conn_check_session_set_transport_param() succeeded\n");

    status = conn_check_session_initiate_check(h_inst, h_session);
    if (status != STUN_OK)
        printf ("conn_check_session_initiate_check() returned error %d\n", status);
    else
        printf ("conn_check_session_initiate_check() succeeded\n");

#if 0
    status = conn_check_session_send_message(h_inst, h_session, STUN_METHOD_ALLOCATE, STUN_REQUEST);
    if (status != STUN_OK)
        printf ("conn_check_session_send_message() returned error %d\n", status);
    else
        printf ("conn_check_session_send_message() succeeded\n");
#endif

#if 0
    status = stun_msg_destroy(h_msg);
    if (status != STUN_OK)
        printf ("stun_msg_destroy() returned error %d\n", status);
    else
        printf ("stun_msg_destroy() succeeded\n");
#endif


    printf ("**************************************************************\n");

    buf = (unsigned char *) platform_malloc (TRANSPORT_MTU_SIZE);

    while (1) {

        bytes = platform_socket_recvfrom(
                sockfd_cc, buf, TRANSPORT_MTU_SIZE, 0, address, &port);

        printf("Received packet from %s:%d\nData: %s\n\n", 
                                                address, port, buf);

        printf ("**************************************************************\n");

        status = stun_msg_decode(buf, bytes, &h_rcvdmsg);
        if (status != STUN_OK)
            printf ("stun_msg_decode() returned error %d\n", status);
        else
            printf ("stun_msg_decode() succeeded\n");

        status = conn_check_session_inject_received_msg(h_inst, h_session, h_rcvdmsg);
    }

#if 0

    status = stun_txn_instance_find_transaction(h_txn_inst, h_rcvdmsg, &h_recvtxn);
    if (status != STUN_OK)
        printf ("stun_txn_instance_find_transaction() returned error %d\n", status);
    else
        printf ("stun_txn_instance_find_transaction() succeeded %p\n", h_recvtxn);

    status = stun_txn_inject_received_msg(h_txn_inst, h_recvtxn, h_rcvdmsg);
    if (status == STUN_OK)
        printf ("stun_txn_inject_received_msg() succeeded %p\n", h_recvtxn);
    else if (status == STUN_TERMINATED)
    {
        printf ("Transaction terminated... destroying transaction %p\n", h_recvtxn);
        stun_destroy_txn(h_txn_inst, h_recvtxn, false, true);
        printf ("Destroyed transaction\n");
    }
    else
        printf ("stun_txn_instance_find_transaction() returned error %d\n", status);

    printf ("**************************************************************\n");

    stun_msg_get_method(h_rcvdmsg, &method);
    stun_msg_get_class(h_rcvdmsg, &class_type);
    stun_msg_get_num_attributes(h_rcvdmsg, &num_attrs);

    printf ("received message method is %d and class is %d\n", method, class_type);
    printf ("number of attributes in received message: %d\n", num_attrs);

    if (class_type == STUN_ERROR_RESP)
    {
        u_int32 error_code;
        handle h_txn, h_msg;
        num = 5;
        status = stun_msg_get_specified_attributes(
                        h_rcvdmsg, STUN_ATTR_ERROR_CODE, ah_attr, &num);
        if (status != STUN_OK)
            printf ("stun_msg_get_specified_attributes() returned error %d for error code attr\n", status);
        else
            printf ("stun_msg_get_specified_attributes() succeeded for error code attr\n");

        status = stun_attr_error_code_get_error_code(ah_attr[0], &error_code);
        if (status != STUN_OK)
            printf ("stun_attr_error_code_get_error_code() returned error %d for error code attr\n", status);
        else
            printf ("stun_attr_error_code_get_error_code() succeeded for error code attr\n");

        printf ("ERROR code: %d\n", error_code);

        h_msg = app_create_alloc_req_with_credentials(h_rcvdmsg);
        if (h_msg == NULL)
            printf ("app_create_alloc_req_with_credentials() failed\n");

        status = stun_create_txn(h_txn_inst, STUN_CLIENT_TXN, STUN_UNRELIABLE_TRANSPORT, &h_txn);
        if (status != STUN_OK)
            printf ("stun_create_txn() returned error %d\n", status);
        else
            printf ("stun_create_txn() succeeded\n");

        status = stun_txn_send_stun_message(h_txn_inst, h_txn, h_msg);
        if (status != STUN_OK)
            printf ("stun_txn_send_stun_message() returned error %d\n", status);
        else
            printf ("stun_txn_send_stun_message() succeeded\n");

    }
    else 
    {
        num = 5;
        status = stun_msg_get_specified_attributes(
                        h_rcvdmsg, STUN_ATTR_MAPPED_ADDR, ah_attr, &num);
        if (status != STUN_OK)
            printf ("stun_msg_get_specified_attributes() returned error %d\n", status);
        else
            printf ("stun_msg_get_specified_attributes() succeeded\n");

        num = 16;
        status = stun_attr_mapped_addr_get_addres(ah_attr[0], address, &num);
        if (status != STUN_OK)
            printf ("stun_attr_mapped_addr_get_addres() returned error %d\n", status);
        else
            printf ("stun_attr_mapped_addr_get_addres() succeeded\n");

        printf ("So my MAPPED address is %s\n", address);
    }
#endif

    conn_check_destroy_instance(h_inst);

    return 0;
}
