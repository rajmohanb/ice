
#define MB_ENABLE_TURN

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <msg_layer_api.h>
#include <stun_tlv_api.h>
#include <stun_txn_api.h>



//#define STUN_SRV_IP "198.65.166.165"
//#define STUN_SRV_IP "75.101.138.128"
//#define STUN_SRV_IP "216.146.46.55"
#define STUN_SRV_IP "192.168.1.2"
#define STUN_SRV_PORT 3478

#define TRANSPORT_MTU_SIZE  1500
#define TEST_USER_NAME "toto"
//#define TEST_USER_NAME "rajmohanb@yahoo.com"

handle h_txn_inst, h_txn;
static int sockfd = 0;


void app_timer_expiry_cb (void *timer_id, void *arg)
{
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

    return;
}

s_int32 app_nwk_send_msg (handle h_msg)
{
    int sent_bytes, buf_len, status;
    unsigned char *buf;

    buf = (u_char *) platform_malloc(TRANSPORT_MTU_SIZE);

    status = stun_msg_encode(h_msg, buf, (u_int32 *)&buf_len);
    if (status != STUN_OK)
        printf ("stun_msg_format() returned error %d\n", status);
    else
        printf ("stun_msg_format() succeeded\n");

    if (!sockfd)
    {
        sockfd = platform_create_socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd == -1)
            return STUN_INT_ERROR;
    }

    sent_bytes = platform_socket_sendto(sockfd, buf, 
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


handle app_create_alloc_req_with_credentials(handle h_authresp)
{
    handle h_msg, h_attr[5];
    handle h_temp;
    s_int32 status, num, len;
    u_char buf[1000] = {0};

    status = stun_msg_create(STUN_REQUEST, STUN_METHOD_ALLOCATE, &h_msg);
    if (status != STUN_OK)
        printf ("stun_msg_create() returned error %d\n", status);
    else
        printf ("stun_msg_create() succeeded\n");

    /*================================================================*/

    status = stun_attr_create(STUN_ATTR_USERNAME, &(h_attr[0]));
    if (status != STUN_OK)
        printf ("stun_attr_create() returned error %d\n", status);
    else
        printf ("stun_attr_create() succeeded\n");

    status = stun_attr_username_set_user_name(h_attr[0], TEST_USER_NAME, strlen(TEST_USER_NAME));
    if (status != STUN_OK)
        printf ("stun_attr_username_set_user_name() returned error %d\n", status);
    else
        printf ("stun_attr_username_set_user_name() succeeded\n");

    status = stun_msg_add_attribute(h_msg, h_attr[0]);
    if (status != STUN_OK)
        printf ("stun_msg_add_attribute() returned error %d for USERNAME attr\n", status);
    else
        printf ("stun_msg_add_attribute() succeeded for USERNAME attr\n");

    /*================================================================*/

    status = stun_attr_create(STUN_ATTR_NONCE, &(h_attr[1]));
    if (status != STUN_OK)
        printf ("stun_attr_create() returned error %d\n", status);
    else
        printf ("stun_attr_create() succeeded\n");

    num = 1;
    status = stun_msg_get_specified_attributes(h_authresp, STUN_ATTR_NONCE, &h_temp, &num);
    if (status != STUN_OK)
        printf ("stun_msg_get_specified_attributes() returned error %d\n", status);
    else
        printf ("stun_msg_get_specified_attributes() succeeded\n");

    len = 1000;
    status = stun_attr_nonce_get_nonce(h_temp, buf, &len);
    if (status != STUN_OK)
        printf ("stun_attr_nonce_get_nonce() returned error %d\n", status);
    else
        printf ("stun_attr_nonce_get_nonce() succeeded - nonce length %d\n", len);

    status = stun_attr_nonce_set_nonce(h_attr[1], buf, len);
    if (status != STUN_OK)
        printf ("stun_attr_nonce_set_nonce() returned error %d\n", status);
    else
        printf ("stun_attr_nonce_set_nonce() succeeded\n");

    status = stun_msg_add_attribute(h_msg, h_attr[1]);
    if (status != STUN_OK)
        printf ("stun_msg_add_attribute() returned error %d for USERNAME attr\n", status);
    else
        printf ("stun_msg_add_attribute() succeeded for NONCE attr\n");

    /*================================================================*/

    status = stun_attr_create(STUN_ATTR_REALM, &(h_attr[2]));
    if (status != STUN_OK)
        printf ("stun_attr_create() returned error %d\n", status);
    else
        printf ("stun_attr_create() succeeded\n");

    num = 1;
    status = stun_msg_get_specified_attributes(h_authresp, STUN_ATTR_REALM, &h_temp, &num);
    if (status != STUN_OK)
        printf ("stun_msg_get_specified_attributes() returned error %d\n", status);
    else
        printf ("stun_msg_get_specified_attributes() succeeded\n");

    len = 1000;
    status = stun_attr_realm_get_realm(h_temp, buf, &len);
    if (status != STUN_OK)
        printf ("stun_attr_nonce_get_nonce() returned error %d\n", status);
    else
        printf ("stun_attr_nonce_get_nonce() succeeded - nonce length %d\n", len);

    status = stun_attr_realm_set_realm(h_attr[2], buf, len);
    if (status != STUN_OK)
        printf ("stun_attr_nonce_set_nonce() returned error %d\n", status);
    else
        printf ("stun_attr_nonce_set_nonce() succeeded\n");

    status = stun_msg_add_attribute(h_msg, h_attr[2]);
    if (status != STUN_OK)
        printf ("stun_msg_add_attribute() returned error %d for USERNAME attr\n", status);
    else
        printf ("stun_msg_add_attribute() succeeded for USERNAME attr\n");

    /*================================================================*/

    status = stun_attr_create(STUN_ATTR_REQUESTED_TRANSPORT, &(h_attr[3]));
    if (status != STUN_OK)
        printf ("stun_attr_create() returned error %d\n", status);
    else
        printf ("stun_attr_create() succeeded\n");

    status = stun_attr_requested_transport_set_protocol(h_attr[3], STUN_TRANSPORT_UDP);
    if (status != STUN_OK)
        printf ("stun_attr_req_transport_set_protocol() returned error %d\n", status);
    else
        printf ("stun_attr_req_transport_set_protocol() succeeded\n");

    status = stun_msg_add_attribute(h_msg, h_attr[3]);
    if (status != STUN_OK)
        printf ("stun_msg_add_attribute() returned error %d for USERNAME attr\n", status);
    else
        printf ("stun_msg_add_attribute() succeeded for USERNAME attr\n");

    /*================================================================*/

    status = stun_attr_create(STUN_ATTR_MESSAGE_INTEGRITY, &(h_attr[4]));
    if (status != STUN_OK)
        printf ("stun_attr_create() returned error %d\n", status);
    else
        printf ("stun_attr_create() succeeded\n");

    status = stun_msg_add_attribute(h_msg, h_attr[4]);
    if (status != STUN_OK)
        printf ("stun_msg_add_attribute() returned error %d for USERNAME attr\n", status);
    else
        printf ("stun_msg_add_attribute() succeeded for USERNAME attr\n");

    /*================================================================*/

    return h_msg;
}


int main (int argc, char *argv[])
{
    handle h_msg, h_attr, h_rcvdmsg, ah_attr[5], h_recvtxn;
    s_int32 status, len, num_attrs;
    u_char *buf, address[16], port;
    int addrlen, bytes, num;
    struct sockaddr_in stun_srvr;
    enum_stun_method_type method;
    enum_stun_msg_type class_type;
    struct_stun_txn_instance_callbacks app_cbs;

    /** initialize platform lib */
    platform_init();

    status = stun_txn_create_instance(&h_txn_inst);
    if (status != STUN_OK)
        printf ("stun_txn_create_instance() returned error %d\n", status);
    else
        printf ("stun_txn_create_instance() succeeded\n");

    app_cbs.nwk_cb = app_nwk_send_msg;
    app_cbs.start_timer_cb = app_start_timer;
    app_cbs.stop_timer_cb = app_stop_timer;

    status = stun_txn_instance_set_callbacks(h_txn_inst, &app_cbs);
    if (status != STUN_OK)
        printf ("stun_txn_instance_set_callbacks() returned error %d\n", status);
    else
        printf ("stun_txn_instance_set_callbacks() succeeded\n");


    status = stun_msg_create(STUN_REQUEST, STUN_METHOD_ALLOCATE, &h_msg);
    if (status != STUN_OK)
        printf ("stun_msg_create() returned error %d\n", status);
    else
        printf ("stun_msg_create() succeeded\n");

    status = stun_attr_create(STUN_ATTR_SOFTWARE, &h_attr);
    if (status != STUN_OK)
        printf ("stun_attr_create() returned error %d\n", status);
    else
        printf ("stun_attr_create() succeeded\n");

    status = stun_attr_software_set_value(h_attr, "oooooooooo Technologies STUN stack 1.0");
    if (status != STUN_OK)
        printf ("stun_attr_software_set_value() returned error %d\n", status);
    else
        printf ("stun_attr_software_set_value() succeeded\n");

#if 0
    status = stun_msg_add_attribute(h_msg, h_attr);
    if (status != STUN_OK)
        printf ("stun_msg_add_attribute() returned error %d\n", status);
    else
        printf ("stun_msg_add_attribute() succeeded\n");
#endif


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

#if 0
    status = stun_msg_destroy(h_msg);
    if (status != STUN_OK)
        printf ("stun_msg_destroy() returned error %d\n", status);
    else
        printf ("stun_msg_destroy() succeeded\n");
#endif


    printf ("**************************************************************\n");

    buf = (unsigned char *) platform_malloc (TRANSPORT_MTU_SIZE);

    if (!sockfd)
    {
        sockfd = platform_create_socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd == -1)
            return STUN_INT_ERROR;
    }
    bytes = platform_socket_recvfrom(sockfd, buf, TRANSPORT_MTU_SIZE, 0, address, &port);

    printf("Received packet from %s:%d\nData: %s\n\n", address, port, buf);

    printf ("**************************************************************\n");

    status = stun_msg_decode(buf, bytes, &h_rcvdmsg);
    if (status != STUN_OK)
        printf ("stun_msg_decode() returned error %d\n", status);
    else
        printf ("stun_msg_decode() succeeded\n");

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

    stun_txn_destroy_instance(h_txn_inst);

    return 0;
}
