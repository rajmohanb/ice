/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2010, MindBricks Technologies               *
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

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


#include <math.h>
#include "stun_base.h"
#include "msg_layer_api.h"
#include "conn_check_api.h"
#include "ice_api.h"
#include "ice_int.h"
#include "ice_addr_sel.h"
#include "ice_utils.h"


s_char *cand_pair_states[] =
{
    "ICE_CP_FROZEN",
    "ICE_CP_WAITING",
    "ICE_CP_INPROGRESS",
    "ICE_CP_SUCCEEDED",
    "ICE_CP_FAILED",
};



int32_t ice_utils_get_highest_priority_nominated_valid_pair(
        ice_media_stream_t *media, uint32_t comp_id, ice_cand_pair_t **nom_pair)
{
    uint32_t i;
    ice_cand_pair_t *pair, *high_pair;
    uint64_t prio = 0;

    high_pair = NULL;
    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        pair = &media->ah_valid_pairs[i];
        if(pair->local == NULL) continue;

        if((pair->local->comp_id == comp_id) && (pair->priority > prio))
        {
            prio = pair->priority;
            high_pair = pair;
        }
    }

    if (high_pair == NULL)
    {
        ICE_LOG(LOG_SEV_WARNING,
                "unable to get highest priority nominated pair "\
                "for comp id %d", comp_id);
        return STUN_NOT_FOUND;
    }

    *nom_pair = high_pair;
    return STUN_OK;
}



/**
 * This routine is used for only lite implementations since there is only
 * always just a single candidate pair in the valid list per component
 */
int32_t ice_utils_get_nominated_valid_pair(
        ice_media_stream_t *media, uint32_t comp_id, ice_cand_pair_t **nom_pair)
{
    uint32_t i;
    ice_cand_pair_t *pair;
    bool_t found = false;

    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        pair = &media->ah_valid_pairs[i];
        if(pair->local == NULL) continue;

        if(pair->local->comp_id == comp_id)
        {
            found = true;
            break;
        }
    }

    if (found == false)
    {
        ICE_LOG(LOG_SEV_WARNING,
                "unable to get highest priority nominated pair "\
                "for comp id %d", comp_id);
        return STUN_NOT_FOUND;
    }

    *nom_pair = pair;
    return STUN_OK;
}



int32_t ice_utils_get_media_params_in_running_state(
            ice_media_stream_t *media, ice_media_params_t *media_params)
{
    int32_t j, k, x;

    for (j = 0; j < media->num_comp; j++)
    {
        ice_media_comp_t *media_comp = &media_params->comps[j];
        k = 0;

        for (x = 0; x < ICE_CANDIDATES_MAX_SIZE; x++)
        {
            ice_cand_params_t *media_cand;
            ice_candidate_t *ice_cand = &media->as_local_cands[x];

            if (ice_cand->comp_id == (j+1))
            {
                media_cand = &media_comp->cands[k];
                k++;

                /** copy the candidate info */
                stun_strncpy((char *)media_cand->foundation, 
                                        (char *)ice_cand->foundation, 
                                        ICE_FOUNDATION_MAX_LEN - 1);

                media_cand->component_id = ice_cand->comp_id;
                media_cand->protocol = ice_cand->transport.protocol;
                media_cand->priority = ice_cand->priority;

                media_cand->ip_addr_type = ice_cand->transport.type;
                stun_memcpy(media_cand->ip_addr, 
                                        ice_cand->transport.ip_addr,
                                        ICE_IP_ADDR_MAX_LEN);

                media_cand->port = ice_cand->transport.port;
                media_cand->cand_type = ice_cand->type;

                stun_memcpy(media_cand->rel_addr, 
                                ice_cand->base->transport.ip_addr,
                                ICE_IP_ADDR_MAX_LEN);
                media_cand->rel_port = ice_cand->base->transport.port;

                if(ice_cand->default_cand == true)
                {
                    media_comp->default_dest.host_type = 
                                            ice_cand->transport.type;
                    stun_strncpy((char *)media_comp->default_dest.ip_addr, 
                                    (char *)ice_cand->transport.ip_addr, 
                                    ICE_IP_ADDR_MAX_LEN - 1);
                    media_comp->default_dest.port = ice_cand->transport.port;
                }
            }
        }

        media_comp->num_cands = k;
        media_comp->comp_id = j + 1;

        media_comp->num_remote_cands = 0;
    }

    return STUN_OK;
}



int32_t ice_utils_get_media_params_in_completed_state(
            ice_media_stream_t *media, ice_media_params_t *media_params)
{
    int32_t i, status;
    ice_media_comp_t *media_comp;
    ice_cand_pair_t *prio_pair;
    ice_cand_params_t *cand_param;

    for (i = 0; i < media->num_comp; i++)
    {
        media_comp = &media_params->comps[i];

        media_comp->comp_id = i+1;
 
        /** 
         * get the highest priority nominated pair in 
         * the valid list for this component.
         */
        if (media->ice_session->local_mode == ICE_MODE_LITE)
        {
            status = ice_utils_get_nominated_valid_pair(media, i+1, &prio_pair);
        }
        else
        {
            status = ice_utils_get_highest_priority_nominated_valid_pair(
                                                    media, i+1, &prio_pair);
        }

        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR,
                "Unable to find highest priority nominated "\
                "pair for comp id %d. Error %d", i, status);
            return status;
        }

        /** this pair becomes the default candidate */
        media_comp->default_dest.host_type = prio_pair->local->transport.type;
        stun_strncpy((char *)media_comp->default_dest.ip_addr, 
                        (char *)prio_pair->local->transport.ip_addr, 
                        ICE_IP_ADDR_MAX_LEN - 1);
        media_comp->default_dest.port = prio_pair->local->transport.port;

        /** add this default destination as candidate param */
        media_comp->num_cands = 1;
        cand_param = &media_comp->cands[0];

        stun_strncpy((char *)cand_param->foundation, 
                                (char *)prio_pair->local->foundation, 
                                ICE_FOUNDATION_MAX_LEN - 1);

        cand_param->component_id = prio_pair->local->comp_id;
        cand_param->protocol = prio_pair->local->transport.protocol;
        cand_param->priority = prio_pair->local->priority;

        cand_param->ip_addr_type = prio_pair->local->transport.type;
        stun_memcpy(cand_param->ip_addr, 
                                prio_pair->local->transport.ip_addr,
                                ICE_IP_ADDR_MAX_LEN);

        cand_param->port = prio_pair->local->transport.port;
        cand_param->cand_type = prio_pair->local->type;

        stun_memcpy(cand_param->rel_addr, 
                        prio_pair->local->base->transport.ip_addr,
                        ICE_IP_ADDR_MAX_LEN);
        cand_param->rel_port = prio_pair->local->base->transport.port;
    
        /** 
         * if this agent is in controlling mode, then add remote-candidates 
         * as well. This attribute contains the remote candidates from the
         * highest priority nominated pair in the valid list for each 
         * component of that media stream.
         */
        if(media->ice_session->role == ICE_AGENT_ROLE_CONTROLLING)
        {
            stun_inet_addr_t *remote_cand;

            media_comp->num_remote_cands = 1;
            remote_cand = &media_comp->remote_cands[0];

            remote_cand->host_type = prio_pair->remote->transport.type;
            stun_strncpy((char *)remote_cand->ip_addr, 
                                (char *)prio_pair->remote->transport.ip_addr, 
                                ICE_IP_ADDR_MAX_LEN - 1);
            remote_cand->port = prio_pair->remote->transport.port;
        }
    }

    return STUN_OK;
}



int32_t ice_utils_get_local_media_params(
        ice_media_stream_t *media, ice_media_params_t *media_params)
{
    int32_t status;

    status = ice_utils_get_media_state_change_event(
                                        media, &(media_params->media_state));
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR,
                "unable to get event for media state. Error %d", status);
        return status;
    }

    if (media_params->media_state == ICE_CC_RUNNING)
    {
        ICE_LOG(LOG_SEV_INFO, "Media in ICE_CC_RUNNING");
        status = ice_utils_get_media_params_in_running_state(
                                                    media, media_params);
    }
    else if (media_params->media_state == ICE_CC_COMPLETED)
    {
        ICE_LOG(LOG_SEV_INFO, "Media in ICE_CC_COMPLETED");
        status = ice_utils_get_media_params_in_completed_state(
                                                    media, media_params);
    }
    else
    {
        /** do not fill any information */
        ICE_LOG(LOG_SEV_ERROR, "TBD????????????????????");
    }

    media_params->num_comps = media->num_comp;

    /** copy media credentials */
    stun_strncpy(media_params->ice_ufrag, 
                            media->local_ufrag, ICE_MAX_UFRAG_LEN - 1);
    stun_strncpy(media_params->ice_pwd, media->local_pwd, ICE_MAX_PWD_LEN - 1);

    media_params->h_media = (handle) media;

    return STUN_OK;
}



int32_t ice_utils_set_peer_media_params(
        ice_media_stream_t *media, ice_media_params_t *media_params)
{
    uint32_t j, k, x = 0;
    ice_candidate_t *cand;

    /** store the number of components of peer */
    media->num_peer_comp = media_params->num_comps;

    /** reset the existing remote candidate parameter information */
    stun_memset(media->as_remote_cands, 0, 
            sizeof(ice_candidate_t) * ICE_CANDIDATES_MAX_SIZE);
    stun_memset(media->peer_ufrag, 0, sizeof(char) * ICE_MAX_UFRAG_LEN);
    stun_memset(media->peer_pwd, 0, sizeof(char) * ICE_MAX_PWD_LEN);

    for (j = 0; j < media_params->num_comps; j++)
    {
        ice_media_comp_t *peer_comp = &media_params->comps[j];

        if (peer_comp == NULL) continue;

        for (k = 0; k < peer_comp->num_cands; k++)
        {
            ice_cand_params_t *peer_cand = &peer_comp->cands[k];

            if (peer_cand == NULL) continue;

            cand = &media->as_remote_cands[x];

            /**
             * There is a current limitation in the spec that the ip
             * address type is not notified as part of the sdp
             * attribute. This has to be identified by the ice agent
             * by looking at the length of the ip address string and
             * by parsing it.
             */
            cand->transport.type = peer_cand->ip_addr_type;

            stun_memcpy(cand->transport.ip_addr, 
                            peer_cand->ip_addr, ICE_IP_ADDR_MAX_LEN);

            cand->transport.port = peer_cand->port;
            cand->transport.protocol = peer_cand->protocol;

            cand->type = peer_cand->cand_type;
            cand->priority = peer_cand->priority;
            stun_memcpy(cand->foundation, 
                    peer_cand->foundation, ICE_FOUNDATION_MAX_LEN);

            /** 
             * the comp id is present at two places in the data provided
             * by the application. One at comp level and the other at each
             * candidate level. The following is just incase of a scenario
             * where the the application does not update at both places.
             */
            if (peer_cand->component_id)
                cand->comp_id = peer_cand->component_id;
            else
                cand->comp_id = peer_comp->comp_id;

            /** 
             * should we care about the following?
             * base, transport_param, default_cand 
             */

            x++;
        }

        /** sec 9.2.3 Lite implementation on receiving remote offer */
        if (peer_comp->num_remote_cands > 0)
        {
            int32_t count, i = 0;
            ice_cand_pair_t *valid_pair;

            for (count = 0; count < peer_comp->num_remote_cands; count++)
            {
                valid_pair = &media->ah_valid_pairs[i];

                /** set remote candidate */
                valid_pair->remote->transport.type = 
                                        peer_comp->default_dest.host_type;
                stun_memcpy(valid_pair->remote->transport.ip_addr, 
                                        peer_comp->default_dest.ip_addr, 
                                        ICE_IP_ADDR_MAX_LEN);
                valid_pair->remote->transport.port = 
                                        peer_comp->default_dest.port;

                /** set local candidate */
                valid_pair->local->transport.type = 
                                    peer_comp->remote_cands[count].host_type;
                stun_memcpy(valid_pair->local->transport.ip_addr, 
                                    peer_comp->remote_cands[count].ip_addr, 
                                    ICE_IP_ADDR_MAX_LEN);
                valid_pair->local->transport.port = 
                                    peer_comp->remote_cands[count].port;
            }
        }
    }

    /** copy the credentials */
    stun_strncpy(media->peer_ufrag, 
                        media_params->ice_ufrag, ICE_MAX_UFRAG_LEN - 1);
    stun_strncpy(media->peer_pwd, 
                        media_params->ice_pwd, ICE_MAX_PWD_LEN - 1);

    ICE_LOG(LOG_SEV_INFO, "[ICE_LITE] Added %d remote candidates", x);

    /** reset the existing candidate and valid pairs, if any */
    stun_memset(media->ah_valid_pairs, 0, 
                    sizeof(ice_cand_pair_t) * ICE_MAX_CANDIDATE_PAIRS);
    stun_memset(media->ah_cand_pairs, 0,
                    sizeof(ice_cand_pair_t) * ICE_MAX_CANDIDATE_PAIRS);

    return STUN_OK;
}



uint64_t ice_utils_compute_priority(ice_candidate_t *cand)
{
    uint32_t type_pref;
    uint64_t prio;

    if (cand == NULL) return STUN_INVALID_PARAMS;

    if (cand->type == ICE_CAND_TYPE_HOST)
        type_pref = CAND_TYPE_PREF_HOST_CANDIDATE;
    else if (cand->type == ICE_CAND_TYPE_PRFLX)
        type_pref = CAND_TYPE_PREF_PRFLX_CANDIDATE;
    else if (cand->type == ICE_CAND_TYPE_SRFLX)
        type_pref = CAND_TYPE_PREF_SRFLX_CANDIDATE;
    else if (cand->type == ICE_CAND_TYPE_RELAYED)
        type_pref = CAND_TYPE_PREF_RELAY_CANDIDATE;
    else 
        return STUN_INVALID_PARAMS;

    prio = (pow(2, 24) * type_pref) + 
           (pow(2, 8) * LOCAL_IP_PRECEDENCE) + 
           (256 - cand->comp_id);

    return prio;
}


int32_t ice_utils_compute_foundation(ice_candidate_t *cand)
{
    static uint32_t count = 1;

    if (cand == NULL) return STUN_INVALID_PARAMS;

    stun_snprintf((char *)cand->foundation, 
                    ICE_FOUNDATION_MAX_LEN, "%d", count);

    count++;

    return STUN_OK;
}


int32_t ice_media_utils_compute_candidate_pair_priority(
            ice_media_stream_t *media, ice_cand_pair_t *cand_pair)
{
    ice_session_t *ice_session;
    uint32_t prio_controlling, prio_controlled;
    uint32_t pair_min, pair_max;
    uint32_t temp = 0;

    ice_session = media->ice_session;

    if (ice_session->role == ICE_AGENT_ROLE_CONTROLLING)
    {
        prio_controlling = cand_pair->local->priority;
        prio_controlled = cand_pair->remote->priority;
    }
    else
    {
        prio_controlling = cand_pair->remote->priority;
        prio_controlled = cand_pair->local->priority;
    }

    if (prio_controlling > prio_controlled)
    {
        pair_min = prio_controlled;
        pair_max = prio_controlling;
        temp = 1;
    }
    else
    {
        pair_min = prio_controlling;
        pair_max = prio_controlled;
        temp = 0;
    }

    cand_pair->priority = (pow(2, 32) * pair_min) +
                          ( 2 * pair_max) + temp;

    return STUN_OK;
}


int32_t ice_media_utils_form_candidate_pairs(ice_media_stream_t *media)
{
    uint32_t i, j, k;
    ice_candidate_t *local, *remote;

    k = 0;

    /** form the candidate pairs */
    for (i = 0; i < ICE_CANDIDATES_MAX_SIZE; i++)
    {
        if (media->as_local_cands[i].type == ICE_CAND_TYPE_INVALID)
            continue;

        local = &media->as_local_cands[i];

        for (j = 0; j < ICE_CANDIDATES_MAX_SIZE; j++)
        {
            if (media->as_remote_cands[j].type == ICE_CAND_TYPE_INVALID)
                continue;

            remote = &media->as_remote_cands[j];

            /** 
             * a local candidate is paired with a remote candidate if
             * and only if the two candidates have the same component ID
             * and have the same IP address version
             */
            if ((local->comp_id == remote->comp_id) &&
                (local->transport.type == remote->transport.type) &&
                (local->transport.protocol == remote->transport.protocol))
            {
                ice_cand_pair_t *pair = &media->ah_cand_pairs[k];
                if (k >= ICE_MAX_CANDIDATE_PAIRS)
                {
                    ICE_LOG(LOG_SEV_CRITICAL,
                            "K value %d more than ICE_MAX_CANDIDATE_PAIRS", k);
                }
                k++;

                pair->local = local;
                pair->remote = remote;

                if ((local->default_cand == true) &&
                    (remote->default_cand == true))
                {
                    pair->default_pair = true;
                }
                else
                {
                    pair->default_pair = false;
                }

                /** initialize the pair */
                pair->valid_pair = false;
                pair->nominated = false;

                pair->state = ICE_CP_FROZEN;

                /** compute the pair priority as per sec 5.7.2 */
                ice_media_utils_compute_candidate_pair_priority(media, pair);
            }
        }
    }

    media->num_cand_pairs = k;

    return STUN_OK;
}



void ice_media_utils_dump_cand_pair_stats(ice_media_stream_t *media)
{
    uint32_t i, count = 0;
    ice_cand_pair_t *pair;

    ICE_LOG (LOG_SEV_DEBUG, 
            "===============================================================");

    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        pair = &media->ah_cand_pairs[i];

        if (!pair->local) continue;

        count++;
        ICE_LOG (LOG_SEV_DEBUG, "count: %d state: %s priority: %lld component id: %d local "\
                "cand %p remote cand %p local foundation: %s remote "\
                "foundation: %s\n", count, cand_pair_states[pair->state], pair->priority,
                pair->local->comp_id, pair->local, pair->remote,
                pair->local->foundation, pair->remote->foundation);
    }

    ICE_LOG (LOG_SEV_DEBUG, "Total %d valid pairs for this media\n", count);

    ICE_LOG (LOG_SEV_DEBUG, "===============================================================");

    return;
}



void ice_utils_dump_media_params(ice_media_params_t *media_params)
{
    uint32_t j, k;

    ICE_LOG(LOG_SEV_INFO, 
            "==============================================================");

    ICE_LOG(LOG_SEV_INFO, 
                "\nNumber of components: %d", media_params->num_comps);

    for (j = 0; j < media_params->num_comps; j++)
    {
        ice_media_comp_t *media_comp = &media_params->comps[j];

        ICE_LOG(LOG_SEV_INFO, 
                "\nComponent ID: %d Number of Candidates: %d", 
                media_comp->comp_id, media_comp->num_cands);

        for (k = 0; k < ICE_MAX_GATHERED_CANDS; k++)
        {
            ice_cand_params_t *cand = &media_comp->cands[k];

            if (cand->cand_type == ICE_CAND_TYPE_INVALID)
                continue;

            ICE_LOG(LOG_SEV_INFO, "a=%s %d %d %lld %d %s %d typ %d %s %d",
                    cand->foundation, cand->component_id,
                    cand->protocol, cand->priority, 
                    cand->ip_addr_type, cand->ip_addr, cand->port,
                    cand->cand_type, cand->rel_addr,
                    cand->rel_port);
        }
    }

    ICE_LOG(LOG_SEV_INFO, 
            "\n==============================================================");

    return;
}



int32_t ice_utils_create_conn_check_session(
                    ice_media_stream_t *media, ice_rx_stun_pkt_t *pkt)
{
    int32_t status;
    handle h_cc_inst;
    conn_check_credentials_t cred;

    h_cc_inst = media->ice_session->instance->h_cc_inst;

    status = conn_check_create_session(h_cc_inst, 
                                CC_SERVER_SESSION, &media->h_cc_svr_session);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, 
                "conn_check_create_session() returned error %d\n", status);
        return status;
    }

    status = conn_check_session_set_app_param(h_cc_inst, 
                                                media->h_cc_svr_session, media);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, 
                "conn_check_session_set_app_param() returned error %d\n", status);
        goto ERROR_EXIT;
    }

    stun_memset(&cred, 0, sizeof(cred));
    stun_strncpy((char *)cred.username, 
                        media->local_ufrag, STUN_MAX_USERNAME_LEN - 1);
    stun_strncpy((char *)cred.password, 
                        media->local_pwd, STUN_MAX_PASSWORD_LEN - 1);
    status = conn_check_session_set_local_credentials(
                            h_cc_inst, media->h_cc_svr_session, &cred);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, 
            "setting of local username and pwd returned error %d\n", status);
        goto ERROR_EXIT;
    }

    stun_memset(&cred, 0, sizeof(cred));
    stun_strncpy((char *)cred.username, 
                        media->peer_ufrag, STUN_MAX_USERNAME_LEN - 1);
    stun_strncpy((char *)cred.password, 
                        media->peer_pwd, STUN_MAX_PASSWORD_LEN - 1);
    status = conn_check_session_set_peer_credentials(
                            h_cc_inst, media->h_cc_svr_session, &cred);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, 
            "setting of peer username and pwd returned error %d\n", status);
        goto ERROR_EXIT;
    }

    status = conn_check_session_set_transport_param(
                            h_cc_inst, media->h_cc_svr_session, 
                            pkt->transport_param);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR,
                "conn_check_session_set_transport_param() "\
                "returned error %d\n", status);
        goto ERROR_EXIT;
    }

    status = conn_check_session_set_peer_transport_params(h_cc_inst, 
                            media->h_cc_svr_session,
                            pkt->src.host_type,
                            pkt->src.ip_addr,
                            pkt->src.port);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR,
                "conn_check_session_set_peer_transport_params() "\
                "returned error %d\n", status);
        goto ERROR_EXIT;
    }

    return STUN_OK;

ERROR_EXIT:
    conn_check_destroy_session(h_cc_inst, media->h_cc_svr_session);
    media->h_cc_svr_session = NULL;

    return status;
}



int32_t ice_utils_copy_media_host_candidates(
                ice_api_media_stream_t *src, ice_media_stream_t *dest)
{
    ice_candidate_t *cand;
    ice_media_host_comp_t *host_comp;
    uint32_t i;

    for ( i = 0; i < src->num_comp; i++)
    {
        cand = &dest->as_local_cands[i];
        host_comp = &src->host_cands[i];

        /** transport params */
        cand->transport.type = host_comp->type;
        memcpy(cand->transport.ip_addr, 
                            host_comp->ip_addr, ICE_IP_ADDR_MAX_LEN);
        cand->transport.port = host_comp->port;
        cand->transport.protocol = host_comp->protocol;

        /** component id */
        cand->comp_id = host_comp->comp_id;

        /** 
         * copy the application transport handle. This handle is 
         * valid only to host candidate types.
         * revisit -- should this be moved to media component level?
         */
        cand->transport_param = host_comp->transport_param;

        /** initialize the rest */
        cand->type = ICE_CAND_TYPE_HOST;
        cand->priority = ice_utils_compute_priority(cand);

        /**
         * when a media is added with host candidate, then set this
         * as the default candidate. This is required in ice-lite
         * sessions. In case the session is ice-full, then when
         * the candidates are gathered, then the default candidate
         * is moved based on the configuration.
         */
        cand->default_cand = true;
        cand->base = cand;
    }

    /** compute the foundation ids */
    ice_utils_compute_foundation_ids(dest);

    dest->num_comp = src->num_comp;

    /** 
     * copy ice user fragment and password, used for 
     * authentication of connectivity checks
     */
    stun_memcpy(dest->local_ufrag, src->ice_ufrag, ICE_MAX_UFRAG_LEN);
    stun_memcpy(dest->local_pwd, src->ice_pwd, ICE_MAX_UFRAG_LEN);

    return STUN_OK;
}


int32_t ice_utils_find_media_for_transport_handle(
    ice_session_t *session, handle transport_param, int32_t *index)
{
    uint32_t j, k;
    ice_media_stream_t *media;
    ice_candidate_t *cand;

    for (j = 0; j < ICE_MAX_MEDIA_STREAMS; j++)
    {
        media = session->aps_media_streams[j];

        for (k = 0; k < ICE_CANDIDATES_MAX_SIZE; k++)
        {
            cand = &media->as_local_cands[k];

            if (cand->transport_param == transport_param)
            {
                *index = j;
                ICE_LOG(LOG_SEV_DEBUG, 
                        "Found an existing ICE media stream for "\
                        "transport param %p", transport_param);
                return STUN_OK;
            }
        }
    }

    ICE_LOG(LOG_SEV_DEBUG, 
            "No media stream found for transport param %p", transport_param);
    return STUN_NOT_FOUND;
}


int32_t ice_utils_find_session_for_transport_handle(
    ice_instance_t *instance, handle transport_param, handle *h_session)
{
    uint32_t i, j, k;
    ice_session_t *ice_session;
    ice_media_stream_t *media;
    ice_candidate_t *cand;

    for (i = 0; i < ICE_MAX_CONCURRENT_SESSIONS; i++)
    {
        ice_session = (ice_session_t *)instance->aps_sessions[i];
        if (!ice_session) continue;

        for (j = 0; j < ICE_MAX_MEDIA_STREAMS; j++)
        {
            media = ice_session->aps_media_streams[j];
            if (!media) continue;

            for (k = 0; k < ICE_CANDIDATES_MAX_SIZE; k++)
            {
                cand = &media->as_local_cands[k];

                if (cand->transport_param == transport_param)
                {
                    *h_session = ice_session;
                    ICE_LOG(LOG_SEV_DEBUG, 
                            "Found an existing ICE session for transport param %p", 
                            transport_param);
                    return STUN_OK;
                }
            }
        }
    }

    ICE_LOG(LOG_SEV_DEBUG, 
            "No session found for transport param %p", transport_param);
    return STUN_NOT_FOUND;
}


ice_media_stream_t *
    ice_session_utils_find_media_stream_for_turn_handle(
                    ice_session_t *ice_session, handle h_turn_handle)
{
    uint32_t i, j;
    ice_media_stream_t *media;

    for (i = 0; i < ice_session->num_media_streams; i++)
    {
        media = ice_session->aps_media_streams[i];
        if (!media) continue;

        for (j = 0; j < ICE_MAX_COMPONENTS; j++)
        {
            if (media->h_turn_sessions[j] == h_turn_handle)
            {
                return media;
            }
        }
    }

    return NULL;
}


void ice_utils_compute_foundation_ids(ice_media_stream_t *media)
{
    /** 
     * indicates the number of candidates for which the 
     * foundation has already been calculated 
     */
    uint32_t i, j, count = 0;
    ice_candidate_t *cand1, *cand2;
    bool_t found_similar;

    /**
     * Two candidates have the same foundation when they are "similar" - of
     * the same type and obtained from the same host candidate and STUN
     * server using the same protocol
     */
    for (i = 0; i < ICE_CANDIDATES_MAX_SIZE; i++)
    {
        cand1 = &media->as_local_cands[i];
        found_similar = false;

        if (cand1->type == ICE_CAND_TYPE_INVALID)
            continue;

        for (j = 0; j < i; j++)
        {
            cand2 = &media->as_local_cands[j];

            if (cand2->type == ICE_CAND_TYPE_INVALID)
                continue;

            /** check for same stun server and same host */
            if ((cand2->type == cand1->type) &&
                (cand2->transport.protocol == cand1->transport.protocol))
            {
                stun_strncpy((char *)cand1->foundation, 
                        (char *)cand2->foundation, ICE_FOUNDATION_MAX_LEN - 1);
                found_similar = true;
                break;
            }
        }

        if (found_similar == false)
        {
            /** need to generate foundation id */
            count++;

            snprintf((char *)cand1->foundation, 
                    ICE_FOUNDATION_MAX_LEN, "%d", count);
        }
    }

    return;
}


handle ice_media_utils_get_base_cand_for_comp_id(
                            ice_media_stream_t *media, uint32_t comp_id)
{
    uint32_t i;
    handle base = NULL;

    for (i = 0; i < ICE_CANDIDATES_MAX_SIZE; i++)
    {
        if ((media->as_local_cands[i].comp_id == comp_id) &&
            (media->as_local_cands[i].type == ICE_CAND_TYPE_HOST))
        {
            base = (handle) &media->as_local_cands[i];
            break;
        }
    }

    return base;
}



ice_candidate_t *ice_utils_get_peer_cand_for_pkt_src(
                    ice_media_stream_t *media, stun_inet_addr_t *src)
{
    uint32_t i;
    ice_candidate_t *cand;

    for (i = 0; i < ICE_CANDIDATES_MAX_SIZE; i++)
    {
        cand = &media->as_remote_cands[i];
        if (cand->type == ICE_CAND_TYPE_INVALID) continue;

        if ((cand->transport.type == src->host_type) &&
            (cand->transport.port == src->port) &&
            (stun_strcmp((char *)cand->transport.ip_addr,
                          (char *)src->ip_addr) == 0))
        {
            return cand;
        }
    }

    return NULL;
}



ice_candidate_t *ice_utils_get_local_cand_for_transport_param(
                ice_media_stream_t *media, handle transport_param)
{
    uint32_t i;
    ice_candidate_t *cand;

    for (i = 0; i < ICE_CANDIDATES_MAX_SIZE; i++)
    {
        cand = &media->as_local_cands[i];
        if (cand->type == ICE_CAND_TYPE_INVALID) continue;

        if (cand->transport_param == transport_param)
        {
            return cand;
        }
    }

    return NULL;
}



bool_t ice_media_utils_have_valid_list(ice_media_stream_t *media)
{
    uint32_t i;
    bool_t rtp_valid, rtcp_valid;
    ice_cand_pair_t *valid;

    rtp_valid = rtcp_valid = false;

    ICE_LOG(LOG_SEV_DEBUG, 
            "Number of peer components[%d] for  media handle %p", 
            media->num_peer_comp, media);
    
    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        valid = &media->ah_valid_pairs[i];
        if (valid->local == NULL) continue;

        if (valid->local->comp_id == RTP_COMPONENT_ID)
            rtp_valid = true;
        else if (valid->local->comp_id == RTCP_COMPONENT_ID)
            rtcp_valid = true;
    }

    ICE_LOG(LOG_SEV_DEBUG, "returning from ice_media_utils_have_valid_list()");

    if (rtp_valid == true)
    {
        ICE_LOG(LOG_SEV_DEBUG, 
                "Connectivity check for RTP component has succeeded "\
                "for media %p", media);
    }

    if (rtcp_valid == true)
    {
        ICE_LOG(LOG_SEV_DEBUG, 
                "Connectivity check for RTCP component has succeeded "\
                "for media %p", media);
    }

    if ((rtp_valid == true) && (media->num_peer_comp == 1))
        return true;

    if ((rtp_valid == true) && (rtcp_valid == true))
        return true;
    else 
        return false;
}



int32_t ice_media_utils_copy_selected_pair(ice_media_stream_t *media)
{
    uint32_t i, j = 0;
    ice_cand_pair_t *valid_cp, *backup_cp;

    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        valid_cp = &media->ah_valid_pairs[i];
        if (valid_cp->local == NULL) continue;

        backup_cp = &media->ah_prev_sel_pair[j];

        stun_memcpy(backup_cp, valid_cp, sizeof(ice_cand_pair_t));

        j++;
        if(j >= ICE_MAX_COMPONENTS) break;
    }

    return STUN_OK;
}



int32_t ice_utils_get_session_state_change_event(
                    ice_session_t *session, ice_state_t *event)
{
    int32_t status = STUN_OK;

    switch(session->state)
    {
        case ICE_SES_CC_RUNNING:
            *event = ICE_CC_RUNNING;
            break;

        case ICE_SES_CC_COMPLETED:
            *event = ICE_CC_COMPLETED;
            break;

        case ICE_SES_CC_FAILED:
            *event = ICE_CC_FAILED;
            break;

        default:
            status = STUN_NOT_FOUND;
            break;
    }

    return status;
}



int32_t ice_utils_get_media_state_change_event(
                    ice_media_stream_t *media, ice_state_t *event)
{
    int32_t status = STUN_OK;

    switch(media->state)
    {
        case ICE_MEDIA_CC_RUNNING:
            *event = ICE_CC_RUNNING;
            break;

        case ICE_MEDIA_CC_COMPLETED:
            *event = ICE_CC_COMPLETED;
            break;

        case ICE_MEDIA_CC_FAILED:
            *event = ICE_CC_FAILED;
            break;

        case ICE_MEDIA_IDLE:
        default:
            status = STUN_NOT_FOUND;
            break;
    }

    return status;
}



int32_t ice_media_utils_notify_state_change_event(
                                        ice_media_stream_t *media)
{
    int32_t status;
    ice_state_t event;

    status = ice_utils_get_media_state_change_event(media, &event);

    if (status == STUN_OK)
    {
        media->ice_session->instance->media_state_event_cb(
                    media->ice_session->instance, media->ice_session, 
                    media, event);
    }

    return status;
}



int32_t ice_session_utils_notify_state_change_event(ice_session_t *session)
{
    int32_t status;
    ice_state_t event;

    status = ice_utils_get_session_state_change_event(session, &event);

    if (status == STUN_OK)
    {
        session->instance->session_state_event_cb(
                                        session->instance, session,  event);
    }

    return status;
}



int32_t ice_media_utils_get_valid_list(ice_media_stream_t *media, 
                                    ice_media_valid_pairs_t *valid_pairs)
{
    int32_t i, j;
    ice_cand_pair_t *cand_pair;
    ice_valid_pair_t *valid_pair;

    for (i = 0, j = 0 ; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        cand_pair = &media->ah_valid_pairs[i];
        if (cand_pair->local == NULL) continue;

        if (j >= ICE_MAX_VALID_LIST_PAIRS) break;
        valid_pair = &valid_pairs->pairs[j];

        valid_pair->comp_id = cand_pair->local->comp_id;

        
        valid_pair->local.host_type = cand_pair->local->transport.type;
        stun_strncpy((char *)valid_pair->local.ip_addr, 
                    (char *)cand_pair->local->transport.ip_addr, 
                    ICE_IP_ADDR_MAX_LEN - 1);
        valid_pair->local.port = cand_pair->local->transport.port;


        valid_pair->peer.host_type = cand_pair->remote->transport.type;
        stun_strncpy((char *)valid_pair->peer.ip_addr, 
                        (char *)cand_pair->remote->transport.ip_addr,
                        ICE_IP_ADDR_MAX_LEN - 1);
        valid_pair->peer.port = cand_pair->remote->transport.port;

        valid_pair->nominated = cand_pair->nominated;

        j += 1;
    }

    valid_pairs->h_media = media;
    valid_pairs->num_valid = j;

    return STUN_OK;
}



int32_t ice_utils_determine_session_state(ice_session_t *session)
{
    int32_t status = STUN_OK, index;
    ice_media_stream_state_t lowest_state = ICE_MEDIA_CC_STATE_MAX;
    ice_session_state_t new_session_state = ICE_SES_STATE_MAX;
    ice_media_stream_t *media;

    /**
     * The state of an ice session is based on the state of all the media
     * streams that make up the ice session. The lowest state of a media
     * stream across all the media will determine the state of overall
     * ice session
     */
    for (index = 0; index < ICE_MAX_MEDIA_STREAMS; index++)
    {
        media = session->aps_media_streams[index];
        if (!media) continue;

        if(media->state < lowest_state)
            lowest_state = media->state;
    }

    /** if there are no media streams, then move to IDLE */
    if ((session->num_media_streams == 0) && 
            (lowest_state == ICE_MEDIA_CC_STATE_MAX))
    {
        lowest_state = ICE_MEDIA_CC_RUNNING;
    }

    ICE_LOG(LOG_SEV_DEBUG, 
        "The lowest state across all media streams is %d.", lowest_state);

    switch(lowest_state)
    {
        case ICE_MEDIA_IDLE:
            new_session_state = ICE_SES_IDLE;
            break;

        case ICE_MEDIA_CC_RUNNING:
            new_session_state = ICE_SES_CC_RUNNING;
            break;

        case ICE_MEDIA_CC_COMPLETED:
            new_session_state = ICE_SES_CC_COMPLETED;
            break;

        case ICE_MEDIA_CC_FAILED:
            new_session_state = ICE_SES_CC_FAILED;
            break;

        default:
            ICE_LOG(LOG_SEV_ERROR, 
                "INVALID lowest state across all media streams %d."\
                "unable to determine ice session state", lowest_state);
            status = STUN_INT_ERROR;
            break;
    }

    if ((new_session_state != session->state) && (status == STUN_OK))
    {
        ICE_LOG(LOG_SEV_DEBUG, 
            "ICE session state moving from %d state to NEW state %d",
            session->state, new_session_state);
        session->state = new_session_state;
    }

    return status;
}



int32_t ice_utils_dual_lite_select_valid_pairs(ice_media_stream_t *media)
{
    int32_t comp_loop, i, comp_id, status = STUN_OK;
    int32_t rtp_vp_cnt, rtcp_vp_cnt, vp_index = 0;
    ice_cand_pair_t *vp = &media->ah_valid_pairs[vp_index];
    bool_t addr_sel_reqd = false;

    rtp_vp_cnt = rtcp_vp_cnt = 0;

    /** determine the number of candidate pairs for each component */
    comp_id = RTP_COMPONENT_ID;
    for (comp_loop = 0; comp_loop < ICE_MAX_COMPONENTS; comp_loop++, comp_id++)
    {
        for(i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
        {
            ice_cand_pair_t *cp = &media->ah_cand_pairs[i];
            if (!cp->local) continue;

            if(cp->local->comp_id == comp_id)
            {
                if (comp_id == RTP_COMPONENT_ID)
                    rtp_vp_cnt++;
                else
                    rtcp_vp_cnt++;

                /** copy each of them to the valid pair list */
                stun_memcpy(vp, cp, sizeof(ice_cand_pair_t));
                vp_index++;
                vp = &media->ah_valid_pairs[vp_index];
            }
        }
    }


    if (media->num_peer_comp == 1)
    {
        if ((rtp_vp_cnt == 1) || (rtcp_vp_cnt == 1))
        {
            ice_utils_dual_lite_nominate_available_pair(media);
            media->state = ICE_MEDIA_CC_COMPLETED;
        }
        else if ((rtp_vp_cnt > 1) || (rtcp_vp_cnt > 1))
        {
            /**
             * RFC 5245 sec 8.2.2 Peer Is Lite
             * if there is more than one pair per component, then select a pair
             * based on local policy. Further, the media state should not move
             * to COMPLETED. This is because both the ice lite parties might 
             * have chosen different valid pair. To reconcile this, the 
             * controlling agent must send an updated offer with the 
             * remote-candidates attributes set to the chosen pair.
             *
             * The local policy adopted to select a single pair is by following
             * the procedures of RFC 3484 and using the default policy table 
             * defined there in.
             */
            addr_sel_reqd = true;
        }
        else
        {
            media->state = ICE_MEDIA_CC_FAILED;
        }
    }
    else
    {
        /** implicit assumption - 2 components */

        if ((rtp_vp_cnt == 0) || (rtcp_vp_cnt == 0))
        {
            media->state = ICE_MEDIA_CC_FAILED;
        }
        else if ((rtp_vp_cnt == 1) && (rtcp_vp_cnt == 1))
        {
            ice_utils_dual_lite_nominate_available_pair(media);
            media->state = ICE_MEDIA_CC_COMPLETED;
        }
        else
        {
            /**
             * RFC 5245 sec 8.2.2 Peer Is Lite
             * if there is more than one pair per component, then select a pair
             * based on local policy. Further, the media state should not move
             * to COMPLETED. This is because both the ice lite parties might 
             * have chosen different valid pair. To reconcile this, the 
             * controlling agent must send an updated offer with the 
             * remote-candidates attributes set to the chosen pair.
             *
             * The local policy adopted to select a single pair is by following
             * the procedures of RFC 3484 and using the default policy table 
             * defined there in.
             */
            addr_sel_reqd = true;
        }
    }

    if (addr_sel_reqd == true)
    {
        int32_t j;
        ice_rfc3484_addr_pair_t *pair;
        ice_rfc3484_addr_pair_t addr_pairs[ICE_CANDIDATES_MAX_SIZE];

        comp_id = RTP_COMPONENT_ID;
        for (comp_loop = 0; comp_loop < media->num_peer_comp; 
                                                    comp_loop++, comp_id++)
        {
            j = 0;

            pair = &addr_pairs[j];
            stun_memset(addr_pairs, 0, sizeof(addr_pairs));

            for(i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
            {
                ice_cand_pair_t *vp = &media->ah_valid_pairs[i];
                if (!vp->local) continue;

                if (vp->local->comp_id == comp_id)
                {
                    pair->src = &vp->local->transport;

                    pair->dest = &vp->remote->transport;

                    pair->reachable = false;
                    j++;
                    pair = &addr_pairs[j];
                }
            }

            ice_addr_sel_determine_destination_address(addr_pairs, j);

            for(i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
            {
                ice_cand_pair_t *vp = &media->ah_valid_pairs[i];
                if (!vp->local) continue;

                if (vp->local->comp_id == comp_id)
                {
                    if ((addr_pairs[0].src == &vp->local->transport) &&
                            (addr_pairs[0].dest == &vp->remote->transport))
                    {
                        vp->nominated = true;
                    }
                }
            }
        }
    }
    
    return status;
}


void ice_utils_dual_lite_nominate_available_pair(ice_media_stream_t *media)
{
    uint32_t i;
    
    for(i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        ice_cand_pair_t *vp = &media->ah_valid_pairs[i];
        if (!vp->local) continue;

        vp->nominated = true;
    }

    return;
}



int32_t ice_utils_add_to_valid_pair_list(ice_media_stream_t *media, 
                ice_rx_stun_pkt_t *rx_pkt, conn_check_result_t *check_result)
{
    int32_t i, status;
    ice_cand_pair_t *cp, *free_vp , *cur_np;
    ice_candidate_t *local = NULL;

    free_vp = cur_np = NULL;

    local = ice_utils_get_local_cand_for_transport_param(
                                    media, rx_pkt->transport_param);
    if (local == NULL) return STUN_INT_ERROR;

    /** find a free slot */
    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        cp = &media->ah_valid_pairs[i];
        if (cp->local == NULL)
        {
            if (free_vp == NULL) free_vp = cp;
        }
        else
        {
            /** 
             * note that at any time, there is only a single 
             * nominated valid pair for a media component.
             */
            if ((cp->local->comp_id == local->comp_id) && 
                (cp->nominated == true))
            {
                cur_np = cp;
                /** break? */
            }
        }
    }

    ICE_LOG (LOG_SEV_INFO, 
        "USE-CANDIDATE is set for this connectivity check request");

    if (free_vp == NULL)
    {
        ICE_LOG (LOG_SEV_WARNING, 
            "Exceeded the cofigured list of valid pair entries");
        return STUN_NO_RESOURCE;
    }

    free_vp->remote = 
        ice_utils_get_peer_cand_for_pkt_src(media, &(rx_pkt->src));
    if (free_vp->remote == NULL)
    {
        ice_candidate_t *new_prflx_cand = NULL;

        ICE_LOG (LOG_SEV_INFO, 
            "Binding request from unknown source. Probably a PEER REFLEXIVE candidate");

        /** add a new remote peer reflexive candidate */
        status = ice_utils_add_remote_peer_reflexive_candidate(media, 
                                &(check_result->prflx_addr), local->comp_id, 
                                check_result->prflx_priority, &new_prflx_cand);

        if (status != STUN_OK)
        {
            ICE_LOG (LOG_SEV_INFO, 
                "Error while adding the PEER REFLEXIVE CANDIDATE");
            return status;
        }

        free_vp->remote = new_prflx_cand;
        free_vp->remote->priority = check_result->prflx_priority;
    }
    
    free_vp->local = local;

    ice_media_utils_compute_candidate_pair_priority(media, free_vp);

    ICE_LOG (LOG_SEV_WARNING, 
        "Connectivity check succeeded for component ID %d "\
        "of media %p", free_vp->local->comp_id, media);

    if (cur_np == NULL)
    {
        /** this is the first pair being nominated for the media component */
        free_vp->nominated = true;
    }
    else
    {
        if (cur_np->priority < free_vp->priority)
        {
            free_vp->nominated = true;
            cur_np->nominated = false;

            /** notify the application about the change in the nominated pair */
            ice_utils_notify_misc_event(media, ICE_NEW_NOM_PAIR);
        }
    }

    return STUN_OK;
}



int32_t ice_utils_add_remote_peer_reflexive_candidate(
                        ice_media_stream_t *media, stun_inet_addr_t *peer_addr,
                        uint32_t prflx_comp_id, uint32_t prflx_priority, 
                        ice_candidate_t **new_prflx)
{
    int32_t i;
    ice_candidate_t *prflx_cand;

    for (i = 0; i < ICE_CANDIDATES_MAX_SIZE; i++)
        if(media->as_remote_cands[i].type == ICE_CAND_TYPE_INVALID) break;

    if (i == ICE_CANDIDATES_MAX_SIZE)
    {
        ICE_LOG(LOG_SEV_ERROR,
                "No more free remote candidates available to add the peer "\
                "reflexive candidate. Reached the maximum configured "\
                "limit %d.", i);

        return STUN_NO_RESOURCE;
    }

    /** 
     * the mapped address is not part of the local candidate list.
     * This is a candidate - a peer reflexive candidate.
     */
    prflx_cand = &media->as_remote_cands[i];

    /** transport params */
    prflx_cand->transport.type = peer_addr->host_type;
    memcpy(prflx_cand->transport.ip_addr, 
                        peer_addr->ip_addr, ICE_IP_ADDR_MAX_LEN);
    prflx_cand->transport.port = peer_addr->port;

    /** Note: protocol is assumed to be always UDP */
    prflx_cand->transport.protocol = ICE_TRANSPORT_UDP;

    /** component id */
    prflx_cand->comp_id = prflx_comp_id;

    /** 
     * copy the application transport handle. This handle is 
     * valid only to host candidate types.
     * revisit -- should this be moved to media component level?
     */
    //prflx_cand->transport_param = cp->local->transport_param;

    prflx_cand->type = ICE_CAND_TYPE_PRFLX;

    prflx_cand->priority = prflx_priority;

    prflx_cand->default_cand = false;

    /** TODO = foundation */
    stun_strncpy((char *)prflx_cand->foundation, "4", 1);

    *new_prflx = prflx_cand;

    return STUN_OK;
}



void ice_utils_notify_misc_event(ice_media_stream_t *media, 
                                                ice_misc_event_t event)
{
    ice_session_t *session = media->ice_session;
    ice_instance_t *instance = session->instance;

    instance->misc_event_cb(instance, session, media, event);

    return;
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
