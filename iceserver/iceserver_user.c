/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2013, MindBricks Technologies               *
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
#include <stdlib.h>
#include <time.h>
#include <libpq-fe.h>

#include <stun_base.h>
#include <turns_api.h>
#include <ice_server.h>


typedef struct
{
    uint32_t max_allocs;
    uint32_t max_concur_allocs;

    char *realm;
    char *username;
    char *password;

    uint32_t def_lifetime;
    uint32_t max_bandwidth;

    char *user_id_str;
    uint32_t user_id;
} mb_iceserver_user_record_t;


typedef struct
{
    uint32_t bandwidth_used;
    uint32_t user_id;
    uint32_t allocation_id;
} mb_iceserver_alloc_record_t;


extern mb_ice_server_t g_mb_server;

static char *mb_transports[] = 
{
    "ICE_TRANSPORT_UDP",
    "ICE_TRANSPORT_TCP"
};

static char *get_user_plan = "get_user_record";
static char *alloc_insert_plan = "alloc_insert";
static char *get_alloc_plan = "get_alloc_plan";
static char *alloc_dealloc_update = "alloc_dealloc_update";


/** close connection to database */
void iceserver_db_closeconn(PGconn *conn)
{
    PQfinish(conn);
}


/** establish connection to database */
PGconn *iceserver_db_connect(void)
{
    PGconn *conn = NULL;
    PGresult *result;
    ExecStatusType db_status;
    Oid user_plan_param_types[1] = { 1043 };
    Oid alloc_plan_param_types[1] = { 20 };
    Oid alloc_dealloc_update_plan_param_types[3] = { 1114, 1114, 23 };
    Oid alloc_insert_plan_param_types[10] = 
                    { 1043, 1043, 23, 23, 23, 1114, 1114, 1114, 23, 20 };

    /** make a connection to the database */
    conn = PQconnectdb("user=turnrelay password=turnrelay dbname=turnrelay_development hostaddr=127.0.0.1 port=5432");

    /** check to see that the backend connection was successfully made */
    if (PQstatus(conn) != CONNECTION_OK)
    {
        printf("Connection to database failed");
        iceserver_db_closeconn(conn);
        return NULL;
    }

    printf("Connection to database - OK\n");

    /** 
     * prepare the postgres command, to be 
     * executed later for querying the users table.
     */
    result = PQprepare(conn, get_user_plan, 
                "SELECT * FROM users WHERE username = $1", 1, 
                user_plan_param_types);

    if ((db_status = PQresultStatus(result)) != PGRES_COMMAND_OK)
    {
        printf("PostGres user plan prepare failed\n");
        printf( "%s\n", PQresStatus(db_status));
        printf( "%s\n", PQresultErrorMessage( result ));
        PQclear( result );
        iceserver_db_closeconn(conn);
        return NULL;
    }
 
    printf("User PLAN prepared\n");
    PQclear( result );

    /** 
     * prepare the postgres command, to be executed later 
     * for inserting records into the allocation table.
     */
    result = PQprepare(conn, alloc_insert_plan, 
                "INSERT INTO allocations (username, realm, req_lifetime, "\
                "allotted_lifetime, bandwidth_used, alloc_at, created_at, "\
                "updated_at, user_id, alloc_handle) "\
                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)", 10, 
                alloc_insert_plan_param_types);

    if ((db_status = PQresultStatus(result)) != PGRES_COMMAND_OK)
    {
        printf("PostGres allocation insert plan prepare failed\n");
        printf( "%s\n", PQresStatus(db_status));
        printf( "%s\n", PQresultErrorMessage( result ));
        PQclear( result );
        iceserver_db_closeconn(conn);
        return NULL;
    }
 
    printf("Allocation insert PLAN prepared\n");
    PQclear( result );

    /** 
     * prepare the postgres command, to be executed 
     * later for querying the allocations table.
     */
    result = PQprepare(conn, get_alloc_plan, 
                "SELECT * FROM allocations WHERE alloc_handle = $1", 1, 
                alloc_plan_param_types);

    if ((db_status = PQresultStatus(result)) != PGRES_COMMAND_OK)
    {
        printf("PostGres alloc plan prepare failed\n");
        printf( "%s\n", PQresStatus(db_status));
        printf( "%s\n", PQresultErrorMessage( result ));
        PQclear( result );
        iceserver_db_closeconn(conn);
        return NULL;
    }
 
    printf("Alloc PLAN prepared\n");
    PQclear( result );

    /** 
     * prepare the postgres command, to be executed later for 
     * updating the dealloc column in the allocations table.
     */
    result = PQprepare(conn, alloc_dealloc_update, 
                "UPDATE allocations SET dealloc_at = $1, updated_at = $2 "\
                "WHERE id = $3", 3, alloc_dealloc_update_plan_param_types);

    if ((db_status = PQresultStatus(result)) != PGRES_COMMAND_OK)
    {
        printf("PostGres alloc plan prepare failed\n");
        printf( "%s\n", PQresStatus(db_status));
        printf( "%s\n", PQresultErrorMessage( result ));
        PQclear( result );
        iceserver_db_closeconn(conn);
        return NULL;
    }
 
    printf("Allocation dealloc update PLAN prepared\n");
    PQclear( result );

    return conn;
}


/** search and fetch user record from the database */
int32_t iceserver_db_fetch_user_record(PGconn *conn, 
        mb_ice_server_event_t *event, mb_iceserver_user_record_t *user)
{
    int rows;
    PGresult *result;
    const char *values[1];
    ExecStatusType db_status;

    values[0] = event->username;
    result = PQexecPrepared(conn, get_user_plan, 1, values, NULL, NULL, 0);

    if ((db_status = PQresultStatus(result)) != PGRES_TUPLES_OK)
    {
        printf("Database query failed!\n");
        printf( "%s\n", PQresStatus(db_status));
        printf( "%s\n", PQresultErrorMessage( result ));
        return STUN_INT_ERROR;
    }

    /**
     * Now make sure that we have atleast and only one matching record. If
     * number of records equals 0, then the provided username is not found.
     * so the server needs to reject the allocation request.
     */
    rows = PQntuples(result);
    if (rows == 0)
    {
        printf("Database query returned: no matching account found\n");
        return STUN_NOT_FOUND;
    }

    /**
     * This is possible if we allow accounts to have different realm values.
     * But as of now, we have only one realm which is mindbricks. So no two
     * accounts can have the same username. Tomorrow if we decide to support
     * having different realms, then when searching the database, we need to
     * search based on realm in addition to the username.
     */
    if (rows > 1)
    {
        printf("Application logic error. Found more than one account for "\
               "the provided username value. As per our app requirements, no "\
               "two accounts need to share the same username. BUG???\n");
    }

    /** 
     * currently making use of hard coded value for column number. This might 
     * lead to some issues as new column elements are added and existing ones 
     * are deleted? Better to get the column number using one of the libpq API.
     */

    /** max_allocs */
    user->max_allocs = atoi(PQgetvalue(result, 0, 13));
    printf("MAX ALLOCS => %d\n", user->max_allocs);

    /** max_concur_allocs */
    user->max_concur_allocs = atoi(PQgetvalue(result, 0, 14));
    printf("MAX CONCURRENT ALLOCS => %d\n", user->max_concur_allocs);

    /** realm */
    user->realm = strdup(PQgetvalue(result, 0, 15));
    printf("REALM => %s\n", user->realm);

    /** username */
    user->username = strdup(PQgetvalue(result, 0, 16));
    printf("USERNAME => %s\n", user->username);

    /** password */
    user->password = strdup(PQgetvalue(result, 0, 17));
    printf("PASSWORD => %s\n", user->password);

    /** default lifetime */
    user->def_lifetime = atoi(PQgetvalue(result, 0, 18));
    printf("DEFAULT LIFETIME => %d\n", user->def_lifetime);

    /** max_bandwidth */
    user->max_bandwidth = atoi(PQgetvalue(result, 0, 19));
    printf("MAXIMUM BANDWIDTH ALLOWED => %d\n", user->max_bandwidth);

    /** store the user id */
    user->user_id_str = strdup(PQgetvalue(result, 0, 0));
    user->user_id = atoi(user->user_id_str);
    printf("USER ID => %d\n", user->user_id);

    /** clear result */
    PQclear( result );

    return STUN_OK;
}


int32_t iceserver_db_fetch_allocation_record(PGconn *conn,
        mb_ice_server_event_t *event, mb_iceserver_alloc_record_t *alloc_record)
{
    int rows;
    PGresult *result;
    const char *values[1];
    char alloc_handle[12] = {0};
    ExecStatusType db_status;

    sprintf(alloc_handle, "%u", (unsigned int)event->h_alloc);
    values[0] = alloc_handle;
    result = PQexecPrepared(conn, get_alloc_plan, 1, values, NULL, NULL, 0);

    if ((db_status = PQresultStatus(result)) != PGRES_TUPLES_OK)
    {
        printf("Allocation database query failed!\n");
        printf( "%s\n", PQresStatus(db_status));
        printf( "%s\n", PQresultErrorMessage( result ));
        return STUN_INT_ERROR;
    }

    /**
     * Now make sure that we have atleast and only one matching record. If
     * number of records equals 0, then the provided allocation handle is 
     * not found. This typically should not happen
     */
    rows = PQntuples(result);
    if (rows == 0)
    {
        printf("Database query returned: no matching account found. BUG????\n");
        return STUN_NOT_FOUND;
    }

    if (rows > 1)
    {
        printf("Application logic error. Found more than one allocation "\
               "record for the provided allocation handle value. As per our "\
               "app requirements, the allocation handle returned by the turns"\
               " server is supposed to be unique. BUG???\n");
    }

    /** 
     * currently making use of hard coded value for column number. This might 
     * lead to some issues as new column elements are added and existing ones 
     * are deleted? Better to get the column number using one of the libpq API.
     */

    /** bandwidth used so far */
    alloc_record->bandwidth_used = atoi(PQgetvalue(result, 0, 5));
    printf("BANDWIDTH USED => %d\n", alloc_record->bandwidth_used);

    /** store the user id */
    alloc_record->user_id = atoi(PQgetvalue(result, 0, 10));
    printf("USER ID => %d\n", alloc_record->user_id);

    /** store the allocation id */
    alloc_record->allocation_id = atoi(PQgetvalue(result, 0, 0));
    printf("ALLOCATION ID => %d\n", alloc_record->allocation_id);

    /** clear result */
    PQclear( result );

    return STUN_OK;
}


int32_t iceserver_get_current_time(char *str)
{
    time_t result;
    struct tm *now;

    result = time(NULL);
    now = localtime(&result);
 
    sprintf(str, "%.4d-%.2d-%.2d %d:%d:%d.000000", (now->tm_year+1900), 
            now->tm_mon, now->tm_mday, now->tm_hour, now->tm_min, now->tm_sec);

    return STUN_OK;
}


int32_t iceserver_db_add_allocation_record(PGconn *conn, 
            mb_ice_server_event_t *event, 
            uint32_t allotted_lifetime, mb_iceserver_user_record_t *user)
{
    ExecStatusType db_status;
    const char *values[10];
    PGresult *result;
    char tmp_value1[10] = {0};
    char tmp_value2[15] = {0};
    char tmp_value3[15] = {0};
    char tmp_value4[30] = {0};
    char tmp_value5[12] = {0};

    values[0] = user->username;
    values[1] = user->realm;

    /** requested lifetime */
    sprintf(tmp_value1, "%d", event->lifetime);
    values[2] = tmp_value1;

    /** allotted lifetime */
    sprintf(tmp_value2, "%d", allotted_lifetime);
    values[3] = tmp_value2;

    strcpy(tmp_value3, "0");
    values[4] = tmp_value3;

    iceserver_get_current_time(tmp_value4);
    printf("CURRENT TIME : %s\n", tmp_value4);

    values[5] = tmp_value4;
    values[6] = tmp_value4;
    values[7] = tmp_value4;
    values[8] = user->user_id_str;

    sprintf(tmp_value5, "%u", (unsigned int)event->h_alloc);
    values[9] = tmp_value5;
    printf("Allocation handle to DB: %s\n", tmp_value5);

    result = PQexecPrepared(conn, alloc_insert_plan, 10, values, NULL, NULL, 0);

    if ((db_status = PQresultStatus(result)) != PGRES_COMMAND_OK)
    {
        printf("PostGres new record insertion  failed\n");
        printf( "%s\n", PQresStatus(db_status));
        printf( "%s\n", PQresultErrorMessage( result ));
        PQclear( result );
        return STUN_INT_ERROR;
    }
 
    printf("New allocation RECORD inserted\n");

    PQclear( result );

    return STUN_OK;
}


int32_t iceserver_db_update_dealloc_column(
                PGconn *conn, mb_iceserver_alloc_record_t *alloc_record)
{
    ExecStatusType db_status;
    const char *values[3];
    PGresult *result;
    char tmp_value1[30] = {0};
    char tmp_value2[30] = {0};

    iceserver_get_current_time(tmp_value1);
    printf("CURRENT TIME : %s\n", tmp_value1);

    values[0] = tmp_value1;
    values[1] = tmp_value1;

    /** requested lifetime */
    sprintf(tmp_value2, "%u", alloc_record->allocation_id);
    values[2] = tmp_value2;

    result = PQexecPrepared(
            conn, alloc_dealloc_update, 3, values, NULL, NULL, 0);

    if ((db_status = PQresultStatus(result)) != PGRES_COMMAND_OK)
    {
        printf("PostGres updation of dealloc column in "\
                "allocation table failed\n");
        printf( "%s\n", PQresStatus(db_status));
        printf( "%s\n", PQresultErrorMessage( result ));
        PQclear( result );
        return STUN_INT_ERROR;
    }
 
    printf("Deallocation column in allocation table updated\n");

    PQclear( result );

    return STUN_OK;
}


int32_t mb_iceserver_handle_new_allocation(
                        PGconn *conn, mb_ice_server_event_t *event)
{
    int32_t bytes, status = STUN_OK;
    stun_MD5_CTX ctx;
    mb_ice_server_alloc_decision_t decision;
    mb_iceserver_user_record_t user_record;

    memset(&decision, 0, sizeof(decision));

    printf ("Got an allocation request to approve\n");

    printf ("USERNAME: %s\n", event->username);
    printf ("   REALM: %s\n", event->realm);
    printf ("LIFETIME: %d\n", event->lifetime);
    printf ("PROTOCOL: %s\n", mb_transports[event->protocol]);

    status = iceserver_db_fetch_user_record(conn, event, &user_record);
    if (status == STUN_NOT_FOUND)
    {
        /** TODO - reject the request */
        decision.approved = false;
        decision.code = 0;
    }
    else if (status == STUN_INT_ERROR)
    {
        /** TODO - handle */
        decision.approved = false;
        decision.code = 0;
    }
    else if (status == STUN_OK)
    {
        decision.approved = true;
        decision.code = 0;
    }

    /** 
     * TODO: checks - check at the requested lifetime? suggest provisioned one
     */
    decision.lifetime = 1800;

    /** TODO: checks - And look at protocol? */
     
    /** TODO: check if the user has already reached max number of allocations? */

    /** TODO: check if the user has already reached the max number of concurrent allocations? */

    /** TODO: Check the bandwidth usage? */

    /** TODO: Then decide to either approve or reject the allocation request */

    /** TODO - for now, just go ahead and approve the allocation */
    decision.blob = event->h_alloc;

    /** calculate the hmac key for long-term authentication */
    stun_MD5_Init(&ctx);
    stun_MD5_Update(&ctx, 
            event->username, strlen((char *)event->username));
    stun_MD5_Update(&ctx, ":", 1);

    stun_MD5_Update(&ctx, event->realm, strlen((char *)event->realm));
    stun_MD5_Update(&ctx, ":", 1);

    stun_MD5_Update(&ctx, 
            user_record.password, strlen(user_record.password));

    stun_MD5_Final((u_char *)decision.hmac_key, &ctx);

    /** add a new allocation record to db */
    status = iceserver_db_add_allocation_record(conn, 
                        event, decision.lifetime, &user_record);
    if (status != STUN_OK)
    {
        printf("Insertion of the allocation row into database failed\n");
        return STUN_INT_ERROR;
    }

    /** post */
    bytes = send(g_mb_server.thread_sockpair[1], 
                        &decision, sizeof(decision), 0);
    printf ("Sent [%d] bytes to signaling process\n", bytes);

    if (bytes == -1)
    {
        printf("Sending of allocation decision response failed\n");
        status = STUN_INT_ERROR;
    }

    /** free the memory allocated  for user record */
    free(user_record.realm);
    free(user_record.username);
    free(user_record.password);
    free(user_record.user_id_str);

    return status;
}


int32_t mb_iceserver_handle_deallocation(
                        PGconn *conn, mb_ice_server_event_t *event)
{
    int32_t status;
    mb_iceserver_alloc_record_t alloc_record;
    printf ("Got an deallocation notification\n");

    /** find the allocation record */
    status = iceserver_db_fetch_allocation_record(conn, event, &alloc_record);
    if (status == STUN_NOT_FOUND)
    {
        printf("BUG!!!\n");
        return status;
    }

    status = iceserver_db_update_dealloc_column(conn, &alloc_record);
    if (status != STUN_OK)
    {
        printf("Updating of the dealloc column in allocation record failed\n");
        return status;
    }

    /** TODO - should we update the stats in user record */

    return STUN_OK;
}


void *mb_iceserver_decision_thread(void)
{
    int bytes, status;
    mb_ice_server_event_t event;
    PGconn *conn;

    printf("In am in the decision process now\n");
    printf("Unix domain socket is : %d\n", g_mb_server.thread_sockpair[1]);

    /** first off connect to the postgres server */
    conn = iceserver_db_connect();

    /** get into loop */
    while(1)
    {
        memset(&event, 0, sizeof(event));
        bytes = recv(g_mb_server.thread_sockpair[1], &event, sizeof(event), 0);
        /** TODO - check and error handling */

        if (event.type == MB_ISEVENT_NEW_ALLOC_REQ)
        {
            status = mb_iceserver_handle_new_allocation(conn, &event);
        }
        else if (event.type == MB_ISEVENT_DEALLOC_NOTF)
        {
            status = mb_iceserver_handle_deallocation(conn, &event);
        }

   }

    iceserver_db_closeconn(conn);

    return NULL;
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/

