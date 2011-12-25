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


/*******************************************************************************
*                                                                              *
* This is a reference sample platform abstraction library. As mentioned        *
* elsewhere, the platform library including this file is not part of the       *
* licensed ICE stack deliverable, but has been included in the delivered       *
* source code package in order to help and aid in the integration of the ICE   *
* stack with the application. This reference platform library may make use of  *
* third party and other open source functionality.                             *
*                                                                              *
*******************************************************************************/


#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <semaphore.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>

#include <stun_base.h>

#ifndef SHA_DIGESTSIZE
#define SHA_DIGESTSIZE  20
#endif

#ifndef SHA_BLOCKSIZE
#define SHA_BLOCKSIZE   64
#endif

#ifndef MD5_DIGESTSIZE
#define MD5_DIGESTSIZE  16
#endif

#ifndef MD5_BLOCKSIZE
#define MD5_BLOCKSIZE   64
#endif

#define PLATFORM_MAX_IPV4_ADDR_LEN  16


unsigned int compute_crc32(const unsigned char *s, unsigned int n);


typedef struct tag_timer_node {
    unsigned int duration;
    unsigned int elapsed_time;
    unsigned int timer_id;
    void *arg;
    timer_expiry_callback timer_fxn;
    struct tag_timer_node *next;
    struct tag_timer_node *prev;
} struct_timer_node;

#ifdef PLATFORM_USE_MISC_API
static struct_timer_node *timer_head = NULL;
static timer_t timerid;
static sem_t timer_mutex;
static unsigned int app_timer_id = 0;
bool app_timer_id_wraparound = false;
unsigned long last_timestamp;


static unsigned long platform_get_current_time (void) 
{
    struct timespec  time_spec;
    clock_gettime (CLOCK_REALTIME, &time_spec);
    return (((unsigned long)time_spec.tv_sec)  * 1000 + ((unsigned long)time_spec.tv_nsec/1000000));
}


/* sys_timer_handler(int sig, siginfo_t *si, void *uc) */
static void
sys_timer_handler(union sigval sig_val)
{
    struct_timer_node *node;
    
    sem_wait(&timer_mutex);

    /** run through the list */
    node = timer_head;

    if (node == NULL)
    {
        last_timestamp = platform_get_current_time();
        sem_post(&timer_mutex);
        return;
    }

    while (node != NULL)
    {
        node->elapsed_time += platform_get_current_time() - last_timestamp;

        if (node->elapsed_time > node->duration)
        {
            struct_timer_node *temp = node;

            if (node->prev) node->prev->next = temp->next;
            if (temp->next) temp->next->prev = node->prev;
            node = temp->next;

            if (timer_head == temp) timer_head = temp->next;

            ICE_LOG (LOG_SEV_DEBUG, 
                "[TIMER]: Timer id %d fired, about to notify app\n", 
                temp->timer_id);

            sem_post(&timer_mutex);
            temp->timer_fxn((void *)temp->timer_id, temp->arg);
            sem_wait(&timer_mutex);

            ICE_LOG (LOG_SEV_DEBUG, "[TIMER]: Freeing %d\n", temp->timer_id);
            platform_free(temp);
            ICE_LOG (LOG_SEV_DEBUG, "[TIMER]: Freed timer node\n");
        }
        else
        {
            node = node->next;
        }
    }
    
    last_timestamp = platform_get_current_time();

    sem_post(&timer_mutex);

    return;
}


static bool platform_timer_init(void)
{
#if 0
    struct sigaction sa;
#endif
    struct sigevent sev;
    struct itimerspec its;
           
    if (sem_init(&timer_mutex, 0, 1) == 0)
    {
        //ICE_LOG (LOG_SEV_INFO, "semaphore created\n");
        ;
    }
    else
    {
        ICE_LOG (LOG_SEV_INFO, "semaphore creation failed\n");
    }
   
#if 0 
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sa.sa_sigaction = sys_timer_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGRTMIN, &sa, NULL) == -1)
        return false;
#endif

#if 0
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGRTMIN;
#else
    sev.sigev_notify = SIGEV_THREAD;
    sev.sigev_notify_function = sys_timer_handler;
    sev.sigev_notify_attributes = NULL;
#endif
    sev.sigev_value.sival_ptr = &timerid;
    if (timer_create(CLOCK_REALTIME, &sev, &timerid) == -1)
        return false;

    timer_head = NULL;
    app_timer_id = 0;
    app_timer_id_wraparound = false;
    last_timestamp = platform_get_current_time();

    ICE_LOG (LOG_SEV_INFO, "timer ID is 0x%lx\n", (long) timerid);

    /* arm the timer */
    its.it_value.tv_sec = 0;
    its.it_value.tv_nsec = PLATFORM_TIMER_PERIODIC_TIME_VALUE * 1000000;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = PLATFORM_TIMER_PERIODIC_TIME_VALUE * 1000000;

    if (timer_settime(timerid, CLOCK_REALTIME, &its, NULL) == -1)
        return NULL;


    return true;
}

static void platform_timer_exit(void)
{
    struct_timer_node *node, *temp;

    if (timer_delete(timerid) != 0)
        ICE_LOG (LOG_SEV_ERROR, "timer_delete() failed\n");

    sem_destroy(&timer_mutex);
    node = timer_head;

    while (node != NULL)
    {
        temp = node;
        node = node->next;
        platform_free(temp);
    }

    return;
}

bool platform_init(void)
{
    platform_timer_init();

    return true;
}

void platform_exit(void)
{
    platform_timer_exit();

    return;
}
#endif /*End of PLATFORM_USE_MISC_API*/

void *platform_malloc(unsigned int size)
{
    return malloc(size);
}

void *platform_calloc(unsigned int nmemb, unsigned int size)
{
    return calloc(nmemb, size);
}

void *platform_memset(void *s, int c, size_t n)
{
    return memset(s, c, n);
}

void *platform_memcpy(void *dest, void *src, unsigned int n)
{
    return memcpy(dest, src, n);
}

int platform_memcmp(void *s1, void *s2, unsigned int n)
{
    return memcmp(s1, s2, n);
}

void platform_free(void *obj)
{
    free(obj);
}

#ifdef PLATFORM_USE_MISC_API
void *platform_start_timer(int duration, 
                                timer_expiry_callback timer_cb, void *arg)
{
    struct_timer_node *new_node;

    new_node = (struct_timer_node *) 
                platform_malloc (sizeof(struct_timer_node));
    if (new_node == NULL) return NULL;

    new_node->duration = duration;
    new_node->timer_fxn = timer_cb;
    new_node->arg = arg;
    new_node->elapsed_time = 0;

    new_node->timer_id = ++app_timer_id;
    if (new_node->timer_id == 0xFFFFFFFF)
    { 
        /** TODO:
         * check if this timer id still exists in the list
         */
        app_timer_id = 0; 
    }

    sem_wait(&timer_mutex);

    /** insert at the start of the list */
    new_node->next = timer_head;
    new_node->prev = NULL;
    if (timer_head) timer_head->prev = new_node;
    timer_head = new_node;

    sem_post(&timer_mutex);

    ICE_LOG (LOG_SEV_DEBUG, 
        "[TIMER]: Added timer node %p for %d ms\n", new_node, duration);
    ICE_LOG (LOG_SEV_DEBUG,
        "[TIMER]: returned Timer handle is %d and arg is %p\n", 
        new_node->timer_id, new_node->arg);

    return (void *)new_node->timer_id;
}

bool platform_stop_timer(void *timer_id)
{
    struct_timer_node *node;
    bool found = false;

    sem_wait(&timer_mutex);

    node = timer_head;

    while (node != NULL)
    {
        if (timer_id == (void *)node->timer_id)
        {
            struct_timer_node *temp = node;

            if (node->prev) node->prev->next = temp->next;
            if (node->next) node->next->prev = temp->prev;
            node = temp->next;

            if (timer_head == temp) timer_head = temp->next;

            ICE_LOG (LOG_SEV_DEBUG, 
                "[TIMER]: Timer id %d found and freed. Arg %p\n", 
                temp->timer_id, temp->arg);

            ICE_LOG (LOG_SEV_DEBUG, "Freeing node %p\n", temp);
            platform_free(temp);
            
            found = true;
            break;
        }
        else
        {
            node = node->next;
        }
    }

    sem_post(&timer_mutex);

    return found;
}


unsigned int platform_create_socket(int domain, int type, int protocol)
{
    return socket(domain, type, protocol);
}

unsigned int platform_bind_socket(int sockfd, struct sockaddr *addr, int addrlen)
{
    return bind(sockfd, addr, addrlen);
}

unsigned int platform_socket_send(int sock_fd, 
        unsigned char *buf, unsigned int len, int flags)
{
    int bytes = send(sock_fd, buf, len, flags);
    ICE_LOG(LOG_SEV_DEBUG, "[PLATFORM] Sent %d bytes", bytes);

    return bytes;
}


unsigned int platform_socket_sendto(int sock_fd, 
        unsigned char *buf, unsigned int len, int flags, int family, 
        unsigned int dest_port, char *dest_ipaddr)
{
#ifdef ICE_IPV6
    struct sockaddr_in6 stun_srvr;
#else
    struct sockaddr_in stun_srvr;
#endif
    int bytes;

    platform_memset((char *) &stun_srvr, 0, sizeof(stun_srvr));

#ifdef ICE_IPV6
    stun_srvr.sin6_family = family;
    stun_srvr.sin6_port = htons(dest_port);
    stun_srvr.sin6_scope_id = htonl(64);
    bytes = inet_pton(family, dest_ipaddr, &stun_srvr.sin6_addr);
#else
    stun_srvr.sin_family = family;
    stun_srvr.sin_port = htons(dest_port);
    bytes = inet_pton(family, dest_ipaddr, &stun_srvr.sin_addr);
#endif
    if (bytes != 1) {
        perror("inet_pton:");
        ICE_LOG (LOG_SEV_ERROR, "inet_pton() failed %d\n", bytes);
        return 0;
    }

    bytes = sendto(sock_fd, buf, len, flags, 
               (struct sockaddr *)&stun_srvr, sizeof(stun_srvr));
    if (bytes == -1)
    {
        perror("sendto:");
    }
    ICE_LOG(LOG_SEV_DEBUG, "[PLATFORM] sent %d bytes\n", bytes);

    return bytes;
}


unsigned int platform_socket_listen(
        int *sockfd_list, int num_fd, int *sockfd_act_list)
{
    unsigned int max_fd, i;
    int ret, *loop_fd;
    fd_set rfds;

    FD_ZERO(&rfds);

    loop_fd = sockfd_list;

    max_fd = 0;
    for (i=0; i < num_fd; i++)
    {
        FD_SET(*loop_fd, &rfds);
        if (max_fd < *loop_fd) max_fd = *loop_fd;
        loop_fd++;
    }

    while (1)
    {
        ret = select(max_fd+1, &rfds, NULL, NULL, NULL);
        if ((ret == -1) && (errno == EINTR)) continue;

        if(ret == -1)
        {
            ICE_LOG(LOG_SEV_ERROR, "Select system call returned error");
            return -1;
        }

        break;
    }

    loop_fd = sockfd_list;
    i = 0;
    do
    {
        if (FD_ISSET(*loop_fd, &rfds))
        {
            *sockfd_act_list = *loop_fd;
            sockfd_act_list++;
            i++;
        }
        loop_fd++;
    } while (i < ret);

#if 0
    ICE_LOG(LOG_SEV_DEBUG, 
            "[PLATFORM] select returned activity on %d sockets", ret);
#endif

    return ret;
}


unsigned int platform_socket_recv(int sock_fd, 
        unsigned char *buf, unsigned int buf_size, int flags)
{
    unsigned int bytes;

    bytes = recv(sock_fd, buf, buf_size, flags);
    if (bytes == -1)
    {
        perror("recvfrom:");
        return -1;
    }

    ICE_LOG(LOG_SEV_DEBUG, "Received packet on fd %d. %d bytes", sock_fd, bytes);

    return bytes;
}


unsigned int platform_socket_recvfrom(int sock_fd, unsigned char *buf, 
        unsigned int buf_size, int flags, unsigned char *src_ipaddr, 
        unsigned int *src_port)
{
    unsigned int bytes, addrlen;
    struct sockaddr_in stun_srvr;

    memset(&stun_srvr, 0, sizeof(stun_srvr));
    addrlen = sizeof(stun_srvr);

    bytes = recvfrom(sock_fd, buf, buf_size, flags, 
                            (struct sockaddr *)&stun_srvr, &addrlen);

    if (bytes == -1)
    {
        perror("recvfrom:");
        return -1;
    }

    *src_port = ntohs(stun_srvr.sin_port);
    //strcpy((char *)src_ipaddr, inet_ntoa(stun_srvr.sin_addr));
    inet_ntop(AF_INET, &stun_srvr.sin_addr,
                (char *)src_ipaddr, PLATFORM_MAX_IPV4_ADDR_LEN + 1);

    ICE_LOG(LOG_SEV_DEBUG, "[PLATFORM] Received packet on fd %d from %s:%d\n"\
            "Data: %s\n\n", sock_fd, inet_ntoa(stun_srvr.sin_addr), 
            ntohs(stun_srvr.sin_port), buf);

    return bytes;
}
#endif /* End of PLATFORM_USE_MISC_API*/


bool platform_get_random_data(unsigned char *data, unsigned int len)
{
    static int fd = 0;

    if (fd == 0)
    {
        fd = open(DEV_RANDOM_FILE, O_RDONLY );

        if( fd == -1 ) {
            return false;
        }
    }

    read(fd, data, len);
#ifdef PLATFORM_DEBUG
    for ( i = 0; i < len; i++) {
        printf( "%x", data[i]);
    }
    printf("\n");
#endif
    
    /** when do we close this? */
    // close( fd );

#if 0
    /** 
     * in case a particular platform does not support 
     * urandom mechanis,, then this can be made use of.
     */
    static bool_t o_rand_init_done = false;
    u_int32 val1, val2, val3;

    if (o_rand_init_done == false)
    {
        platform_srand(platform_time(NULL));
        o_rand_init_done = true;
    }

    val1 = platform_rand();
    val2 = platform_time(NULL);
    val3 = val1+val2;

    stun_memcpy(txn_id+0, &val1, 4);
    stun_memcpy(txn_id+4, &val2, 4);
    stun_memcpy(txn_id+8, &val3, 4);
    
    return STUN_OK;
#endif

    return true;
}


void platform_log(stun_log_level_t level, char *format, ...)
{
    char buff[150];
    va_list args;
    va_start(args, format );
    snprintf(buff, 150, "%s\n", format);
    vprintf(buff, args );
    va_end(args );
}


#if 0
/** Function to print the digest */
static void pr_sha(FILE* fp, char* s, int t)
{
    int i;
    for (i = 0 ; i < t ; i++)
        fprintf(fp, "%02x", s[i]) ;
    fprintf(fp, "\n") ;
}


static void truncate (
    char*   d1,   /* data to be truncated */
    char*   d2,   /* truncated data */
    int     len   /* length in bytes to keep */
)
{
    int     i ;
    for (i = 0 ; i < len ; i++) d2[i] = d1[i];
}

/** Function to compute the digest */
void platform_hmac_sha
(
  char*    k,     /* secret key */
  int      lk,    /* length of the key in bytes */
  char*    d,     /* data */
  int      ld,    /* length of data in bytes */
  char*    out,   /* output buffer, at least "t" bytes */
  int      t
)
{
    SHA_CTX ictx, octx ;
    char    isha[SHA_DIGESTSIZE], osha[SHA_DIGESTSIZE] ;
    char    key[SHA_DIGESTSIZE] ;
    char    buf[SHA_BLOCKSIZE] ;
    int     i ;

    if (lk > SHA_BLOCKSIZE) {

        SHA_CTX         tctx ;

        SHA1_Init(&tctx) ;
        SHA1_Update(&tctx, k, lk) ;
        SHA1_Final(key, &tctx) ;

        k = key ;
        lk = SHA_DIGESTSIZE ;
    }

    /**** Inner Digest ****/
    SHA1_Init(&ictx) ;

    /* Pad the key for inner digest */
    for (i = 0 ; i < lk ; ++i) buf[i] = k[i] ^ 0x36 ;
    for (i = lk ; i < SHA_BLOCKSIZE ; ++i) buf[i] = 0x36 ;

    SHA1_Update(&ictx, buf, SHA_BLOCKSIZE) ;
    SHA1_Update(&ictx, d, ld) ;
    SHA1_Final(isha, &ictx) ;

    /**** Outter Digest ****/
    SHA1_Init(&octx) ;

    /* Pad the key for outter digest */
    for (i = 0 ; i < lk ; ++i) buf[i] = k[i] ^ 0x5C ;
    for (i = lk ; i < SHA_BLOCKSIZE ; ++i) buf[i] = 0x5C ;

    SHA1_Update(&octx, buf, SHA_BLOCKSIZE) ;
    SHA1_Update(&octx, isha, SHA_DIGESTSIZE) ;

    SHA1_Final(osha, &octx) ;

    /* truncate and print the results */
    t = t > SHA_DIGESTSIZE ? SHA_DIGESTSIZE : t ;
        truncate(osha, out, t) ;
        pr_sha(stdout, out, t) ;

}
#endif

void platform_hmac_sha
(
  char*    k,     /* secret key */
  int      lk,    /* length of the key in bytes */
  char*    d,     /* data */
  int      ld,    /* length of data in bytes */
  char*    out,   /* output buffer, at least "t" bytes */
  int      t
)
{
    HMAC_CTX ctx;

    HMAC_CTX_init(&ctx);
    HMAC_Init(&ctx, k, lk, EVP_sha1());
    HMAC_Update(&ctx, (unsigned char *)d, ld);
    HMAC_Final(&ctx, (unsigned char *)out, (unsigned int *)&t);

    HMAC_CTX_cleanup(&ctx);

    return;
}


uint32_t platform_crc32(uint8_t *data, size_t len)
{
    u_int32_t crc = 0;

    crc = compute_crc32(data, len);

    return crc;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
