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


#include <math.h>
#include "stun_base.h"
#include "msg_layer_api.h"
#include "conn_check_api.h"
#include "turn_api.h"
#include "stun_binding_api.h"
#include "ice_api.h"
#include "ice_int.h"
#include "ice_cand_pair_fsm.h"
#include "ice_utils.h"



s_char *cand_pair_states[] =
{
    "ICE_CP_FROZEN",
    "ICE_CP_WAITING",
    "ICE_CP_INPROGRESS",
    "ICE_CP_SUCCEEDED",
    "ICE_CP_FAILED",
    "ICE_CP_STATE_MAX",
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
        pair = &media->ah_cand_pairs[i];
        if(pair->local == NULL) continue;
        if(pair->valid_pair == false) continue;

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
        pair = &media->ah_cand_pairs[i];
        if(pair->local == NULL) continue;
        if(pair->nominated == false) continue;

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

    if ((media_params->media_state == ICE_CC_RUNNING) ||
        (media_params->media_state == ICE_GATHERED))
    {
        status = ice_utils_get_media_params_in_running_state(
                                                    media, media_params);
    }
    else if (media_params->media_state == ICE_CC_COMPLETED)
    {
        status = ice_utils_get_media_params_in_completed_state(
                                                    media, media_params);
    }
    else
    {
        /** do not fill any information */
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

    /** reset the existing remote candidate parameter information */
    stun_memset(media->as_remote_cands, 0, 
            sizeof(ice_candidate_t) * ICE_CANDIDATES_MAX_SIZE);
    stun_memset(media->peer_ufrag, 0, sizeof(char) * ICE_MAX_UFRAG_LEN);
    stun_memset(media->peer_pwd, 0, sizeof(char) * ICE_MAX_PWD_LEN);

    /** store the number of components of peer */
    media->num_peer_comp = media_params->num_comps;

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
    }

    /** copy the credentials */
    stun_strncpy(media->peer_ufrag, 
                        media_params->ice_ufrag, ICE_MAX_UFRAG_LEN - 1);
    stun_strncpy(media->peer_pwd, 
                        media_params->ice_pwd, ICE_MAX_PWD_LEN - 1);

    ICE_LOG(LOG_SEV_DEBUG, 
        "[ICE MEDIA] remote params ufrag[%s]; pwd[%s]", 
        media->peer_ufrag, media->peer_pwd);

    return STUN_OK;
}



uint64_t ice_utils_compute_candidate_priority(ice_candidate_t *cand)
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
        return 0;

    prio = (pow(2, 24) * type_pref) + 
           (pow(2, 8) * cand->local_pref) + 
           (256 - cand->comp_id);

    return prio;
}


uint64_t ice_utils_compute_peer_reflexive_candidate_priority(
                                                    ice_candidate_t *cand)
{
    uint32_t type_pref;
    uint64_t prio;

    if (cand == NULL) return STUN_INVALID_PARAMS;

    type_pref = CAND_TYPE_PREF_PRFLX_CANDIDATE;

    prio = (pow(2, 24) * type_pref) + 
           (pow(2, 8) * cand->local_pref) + 
           (256 - cand->comp_id);

    return prio;
}



int32_t ice_utils_compute_candidate_foundation(ice_candidate_t *cand)
{
    static uint32_t count = 1;

    if (cand == NULL) return STUN_INVALID_PARAMS;

    stun_snprintf((char *)cand->foundation, 
                    ICE_FOUNDATION_MAX_LEN, "candidate:%d", count);

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
                pair->check_nom_status = false;

                pair->state = ICE_CP_FROZEN;
                pair->media = media;

                /** compute the pair priority as per sec 5.7.2 */
                ice_media_utils_compute_candidate_pair_priority(media, pair);

                if (media->ice_session->role == ICE_AGENT_ROLE_CONTROLLING)
                {
                    if (media->ice_session->instance->nomination_mode == 
                                                ICE_NOMINATION_TYPE_AGGRESSIVE)
                        pair->check_nom_status = true;
                    else
                        pair->check_nom_status = false;
                }
            }
        }
    }

    media->num_cand_pairs = k;

    return STUN_OK;
}



int32_t ice_media_utils_sort_candidate_pairs(ice_media_stream_t *media)
{
    int i, j;
    int test;
    ice_cand_pair_t temp;

    /** we use bubble sort method here for sorting */
    for(i = ICE_MAX_CANDIDATE_PAIRS - 1; i > 0; i--)
    {
        test=0;
        for(j = 0; j < i; j++)
        {
            /** compare neighboring elements */
            if(media->ah_cand_pairs[j].priority < 
                        media->ah_cand_pairs[j+1].priority)
            {
                stun_memcpy(&temp, &media->ah_cand_pairs[j], sizeof(temp));
                stun_memcpy(&media->ah_cand_pairs[j], 
                        &media->ah_cand_pairs[j+1], sizeof(temp));
                stun_memcpy(&media->ah_cand_pairs[j+1], &temp, sizeof(temp));
                test = 1;
            }
        }

        /** exit if the list is sorted! */
        if(test==0) break;
    }
  
    return STUN_OK;
}


int32_t ice_media_utils_prune_checklist(ice_media_stream_t *media)
{
    uint32_t i, j;
    ice_cand_pair_t *pair, *pair_hi, *pair_lo;

    /**
     * first of all, run through the list and for each pair where
     * the local candidate is server reflexive, the server 
     * reflexive candidate must be replaced by it's base.
     */
    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        pair = &media->ah_cand_pairs[i];

        if (!pair->local) continue;

        if (pair->local->type == ICE_CAND_TYPE_SRFLX)
        {
            pair->local = pair->local->base;
        }
    }

#ifdef DEBUG1
    ice_media_utils_dump_cand_pair_stats(media);
#endif

    /**
     * now the actual pruning is done. This is done by removing a pair
     * if it's local and remote candidates are identical to the local
     * and remote candidates of a pair higher up on the priority list.
     */
    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        pair_hi = &media->ah_cand_pairs[i];

        if (!pair_hi->local) continue;

#ifdef DEBUG1
        ICE_LOG (LOG_SEV_DEBUG, "Hi Pair state: %s component id: %d local "\
               "candidate : %p remote candidate: %p\n", 
               cand_pair_states[pair_hi->state], pair_hi->local->comp_id, 
               pair_hi->local, pair_hi->remote);
#endif

        for (j = i+1; j < ICE_MAX_CANDIDATE_PAIRS; j++)
        {
            pair_lo = &media->ah_cand_pairs[j];
        
            if (!pair_lo->local) continue;

#ifdef DEBUG1
            ICE_LOG (LOG_SEV_DEBUG, "Low Pair state: %s component id: %d "\
                    "local candidate : %p remote candidate: %p\n", 
                    cand_pair_states[pair_lo->state], pair_lo->local->comp_id,
                    pair_lo->local, pair_lo->remote);
#endif

            if ((pair_hi->local == pair_lo->local) &&
                (pair_hi->remote == pair_lo->remote))
            {
                stun_memset(pair_lo, 0, sizeof(ice_cand_pair_t));
                ICE_LOG(LOG_SEV_DEBUG, "pruned one candidate pair");
            }

        }

#ifdef DEBUG1
        ICE_LOG (LOG_SEV_DEBUG, 
                "========================================================\n");
#endif
    }

    /**
     * TODO - limiting of the number of connectivity 
     *        checks across all the check lists
     */

    return STUN_OK;
}



int32_t ice_media_utils_compute_initial_states_for_pairs(
                                            ice_media_stream_t *media)
{
#if 0
    uint32_t i;
    ice_cand_pair_t *pair;

    /** 
     * since only one candidate is supported as of now, so there is no use
     * of performing the following step - 
     * For all pairs with the same foundation, it sets the state of the pair
     * with the lowest component ID to Waiting. If there is more than one
     * such pair, the one with the lowest priority is used.
     * TODO
     */

    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        pair = &session->ah_candidate_pairs[i];

        if (!pair->local) continue;

        pair->state = ICE_CND_PAIR_WAITING;
    }
#endif

    return STUN_OK;
}



int32_t ice_media_utils_initialize_cand_pairs(ice_media_stream_t *media)
{
    uint32_t i, j;
    ice_cand_pair_t *outer, *inner, *waiting_pair;

    /**
     * sec 5.7.4 computing states [Applicable for the first media stream]
     * - For all pairs with the same foundation, it sets the state of the
     *   pair with the lowest component ID to Waiting. If there is more
     *   than one such pair, the one with the highest priority is used.
     */

    /** note: this is ugly, need to re-factor */
    for (i =0 ; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        outer = &media->ah_cand_pairs[i];

        if (!outer->local) continue;
        outer->state = ICE_CP_WAITING;
        waiting_pair = outer;

        for (j = 0; j < ICE_MAX_CANDIDATE_PAIRS; j++)
        {
            uint32_t len1, len2;
            inner = &media->ah_cand_pairs[j];

            if (!inner->local) continue;

            if (i == j) continue;

            len1 = strlen((char *)outer->local->foundation);
            len2 = strlen((char *)inner->local->foundation);

            if (len1 != len2) continue;

            if (strncmp((char *)outer->local->foundation, 
                            (char *)inner->local->foundation, len1) == 0)
            {
                len1 = strlen((char *)outer->remote->foundation);
                len2 = strlen((char *)inner->remote->foundation);

                if (len1 != len2) continue;

                if (strncmp((char *)outer->remote->foundation, 
                            (char *)inner->remote->foundation, len1) != 0)
                    continue;

                /** foundations matched */
                if (inner->local->comp_id <= waiting_pair->local->comp_id)
                {
                    /**
                     * note: if there is more than one such pair, the one
                     * with the highest priority is used - tbd
                     */
                    waiting_pair->state = ICE_CP_FROZEN;
                    waiting_pair = inner;
                    waiting_pair->state = ICE_CP_WAITING;

#ifdef DEBUG1
                    ICE_LOG(LOG_SEV_DEBUG, "value i:%d and j:%d", i, j);
                    ICE_LOG(LOG_SEV_DEBUG, 
                            "Waiting pair found for comp id %d foundation %s:%s", 
                            inner->local->comp_id, outer->local->foundation, 
                            inner->local->foundation);
#endif

                }
            }
        }
    }

    return STUN_OK;
}



void ice_media_utils_dump_cand_pair_stats(ice_media_stream_t *media)
{
    uint32_t i, count = 0;
    s_char nom_status[16], valid_status[16], candtype[16];
    ice_cand_pair_t *pair;

    ICE_LOG (LOG_SEV_WARNING, 
            "===============================================================");

    ICE_LOG (LOG_SEV_WARNING, 
            "count: [comp_id] source --> dest state [ priority foundation ]");


    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        pair = &media->ah_cand_pairs[i];

        if (!pair->local) continue;

        if (pair->valid_pair == true)
            stun_strcpy(valid_status, "validated");
        else
            stun_strcpy(valid_status, "NOT validated");

        if (pair->nominated == true)
            stun_strcpy(nom_status, "nominated");
        else if (pair->check_nom_status == true)
            stun_strcpy(nom_status, "nominating");
        else
            stun_strcpy(nom_status, "NOT nominated");

        if (pair->local->type == ICE_CAND_TYPE_HOST)
            stun_strcpy(candtype, "Host");
        else if (pair->local->type == ICE_CAND_TYPE_SRFLX)
            stun_strcpy(candtype, "Server Reflex");
        else if (pair->local->type == ICE_CAND_TYPE_PRFLX)
            stun_strcpy(candtype, "Peer Reflex");
        else if (pair->local->type == ICE_CAND_TYPE_RELAYED)
            stun_strcpy(candtype, "Relayed");
        else
            stun_strcpy(candtype, "Invalid");


        count++;
        ICE_LOG (LOG_SEV_WARNING, 
                "%d: [%d] %s:%d --> %s:%d %s [%s] [%s] [ %lld %s:%s ] [%s]", 
                count, pair->local->comp_id, pair->local->transport.ip_addr, 
                pair->local->transport.port, pair->remote->transport.ip_addr, 
                pair->remote->transport.port, cand_pair_states[pair->state], 
                valid_status, nom_status, pair->priority, 
                pair->local->foundation, pair->remote->foundation, candtype);
    }

    ICE_LOG (LOG_SEV_WARNING, "Total %d valid pairs for this media", count);

    ICE_LOG (LOG_SEV_WARNING, "===============================================================");

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



int32_t ice_media_utils_get_next_connectivity_check_pair(
                    ice_media_stream_t *media, ice_cand_pair_t **pair)
{
    int32_t status;
    uint32_t i, z = 99999;
    ice_cand_pair_t *cand_pair, *hi_prio_pair;

    hi_prio_pair = NULL;
    status = STUN_OK;

    /** section 5.8 - scheduling checks */

    /** first look into triggered check queue */
    if (media->trig_check_list)
    {
        ice_trigger_check_node_t *elem = media->trig_check_list;
        media->trig_check_list = elem->next;

        ICE_LOG(LOG_SEV_INFO, "[ICE] Found a triggered check for cand pair");
        *pair = elem->cp;

        stun_free(elem);
        return STUN_OK;
    }

    /** 
     * if there is no triggered check to be sent, the agent 
     * must choose an ordinary check as follows...
     */

    /** 
     * find the highest priority pair in the check list 
     * that is in the Waiting state 
     */
    for ( i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        cand_pair = &media->ah_cand_pairs[i];
        if (!cand_pair->local) continue;

        if (cand_pair->state != ICE_CP_WAITING) continue;

        if (hi_prio_pair == NULL)
        {
            z = i;
            hi_prio_pair = cand_pair;
            continue;
        }

        if (cand_pair->priority > hi_prio_pair->priority)
            hi_prio_pair = cand_pair;
    }

    if (hi_prio_pair != NULL)
    {
        ICE_LOG(LOG_SEV_DEBUG, "Choosen candidate pair index %d", z);
        *pair = hi_prio_pair;
        return status;
    }

    /** we are here because there is no pair in the WAITING state */
    ICE_LOG(LOG_SEV_DEBUG, 
            "No more candidate pair in the WAITING state. Now need to "\
            "choose the candidate with the highest priority pair in the "\
            "FROZEN state");

    /** 
     * find the highest priority pair in that 
     * check list that is in the FROZEN state 
     */
    for ( i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        cand_pair = &media->ah_cand_pairs[i];
        if (!cand_pair->local) continue;

        if (cand_pair->state != ICE_CP_FROZEN) continue;

        if (hi_prio_pair == NULL)
        {
            z = i;
            hi_prio_pair = cand_pair;
            continue;
        }

        if (cand_pair->priority > hi_prio_pair->priority)
            hi_prio_pair = cand_pair;
    }

    if (hi_prio_pair != NULL)
    {
        ICE_LOG(LOG_SEV_DEBUG, "Choosen candidate pair index %d", z);
        *pair = hi_prio_pair;
        return status;
    }

    /**
     * If there is no pair in the FROZEN state, then terminate the timer
     * for the particular check list
     */
    ICE_LOG(LOG_SEV_DEBUG, 
            "No more candidate pairs left for this checklist. "\
            "So terminating the check list timer for this checklist");

    return STUN_NOT_FOUND;
}



int32_t ice_cand_pair_utils_init_connectivity_check(ice_cand_pair_t *pair)
{
    int32_t status;
    handle h_cc_inst;
    ice_media_stream_t *media;
    conn_check_credentials_t cred;
    conn_check_session_params_t cc_params= {0};

    media = pair->media;
    h_cc_inst = media->ice_session->instance->h_cc_inst;

    ICE_LOG (LOG_SEV_WARNING, 
            " Check: [%d] %s:%d --> %s:%d %s ", pair->local->comp_id, 
            pair->local->transport.ip_addr, pair->local->transport.port,
            pair->remote->transport.ip_addr, pair->remote->transport.port, 
            cand_pair_states[pair->state]);

    status = conn_check_create_session(h_cc_inst, 
                            CC_CLIENT_SESSION, &(pair->h_cc_session));
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, 
                "conn_check_create_session() returned error %d", status);
        goto ERROR_EXIT_PT1;
    }

    status = conn_check_session_set_transport_param(
                                h_cc_inst, pair->h_cc_session, 
                                pair->local->transport_param);

    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_DEBUG, 
            "conn_check_session_set_transport_param() returned error %d", 
            status);
        goto ERROR_EXIT_PT2;
    }

    status = conn_check_session_set_peer_transport_params(h_cc_inst, 
                            pair->h_cc_session, 
                            pair->remote->transport.type, 
                            pair->remote->transport.ip_addr, 
                            pair->remote->transport.port);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_DEBUG, 
            "conn_check_session_set_peer_transport_params() "\
            "returned error %d", status);
        goto ERROR_EXIT_PT2;
    }

    /** set the ice media handle as application handle */
    status = conn_check_session_set_app_param(h_cc_inst, 
                                            pair->h_cc_session, pair);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_DEBUG, 
            "conn_check_session_set_app_param() returned error %d", status);
        goto ERROR_EXIT_PT2;
    }

    /** set local credentials */
    stun_memset(&cred, 0, sizeof(conn_check_credentials_t));
    stun_memcpy(cred.username, media->local_ufrag, STUN_MAX_USERNAME_LEN);
    stun_memcpy(cred.password, media->local_pwd, STUN_MAX_PASSWORD_LEN);
    status = conn_check_session_set_local_credentials(
                                    h_cc_inst, pair->h_cc_session, &cred);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_DEBUG, 
            "conn_check_session_set_local_credentials() returned error %d", 
            status);
        goto ERROR_EXIT_PT2;
    }

    /** set peer credentials */
    stun_memset(&cred, 0, sizeof(conn_check_credentials_t));
    stun_memcpy(cred.username, media->peer_ufrag, STUN_MAX_USERNAME_LEN);
    stun_memcpy(cred.password, media->peer_pwd, STUN_MAX_PASSWORD_LEN);
    status = conn_check_session_set_peer_credentials(
                                    h_cc_inst, pair->h_cc_session, &cred);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_DEBUG, 
            "conn_check_session_set_peer_credentials() returned error %d", 
            status);
        goto ERROR_EXIT_PT2;
    }

    /** set session behavioral parameters  */
    if (media->ice_session->role == ICE_AGENT_ROLE_CONTROLLING)
        cc_params.controlling_role = true;
    else
        cc_params.controlling_role = false;

    cc_params.nominated = pair->check_nom_status;
    cc_params.prflx_cand_priority = 
        ice_utils_compute_peer_reflexive_candidate_priority(pair->local);
    cc_params.tie_breaker = media->ice_session->tie_breaker;
    status = conn_check_session_set_session_params(
                                h_cc_inst, pair->h_cc_session, &cc_params);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_DEBUG, 
            "conn_check_session_set_session_params() returned error %d", 
            status);
        goto ERROR_EXIT_PT2;
    }

    status = conn_check_session_initiate_check(h_cc_inst, pair->h_cc_session);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_DEBUG, 
            "conn_check_session_initiate_check() returned error %d", status);
        goto ERROR_EXIT_PT2;
    }

    return status;

ERROR_EXIT_PT2:
    conn_check_destroy_session(h_cc_inst, pair->h_cc_session);
ERROR_EXIT_PT1:
    return status;
}




int32_t ice_utils_create_conn_check_session(
                    ice_media_stream_t *media, ice_rx_stun_pkt_t *pkt)
{
    int32_t status;
    handle h_cc_inst;
    conn_check_credentials_t cred;
    conn_check_session_params_t cc_params= {0};

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

    /** set session behavioral parameters  */
    if (media->ice_session->role == ICE_AGENT_ROLE_CONTROLLING)
        cc_params.controlling_role = true;
    else
        cc_params.controlling_role = false;

    cc_params.nominated = false; /** not required for incoming checks */
    cc_params.prflx_cand_priority = 0; /** not required for incoming checks */
    cc_params.tie_breaker = media->ice_session->tie_breaker;
    status = conn_check_session_set_session_params(
                    h_cc_inst, media->h_cc_svr_session, &cc_params);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_DEBUG, 
            "conn_check_session_set_session_params() returned error %d", 
            status);
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
        cand->transport.type = host_comp->addr.host_type;
        memcpy(cand->transport.ip_addr, 
                            host_comp->addr.ip_addr, ICE_IP_ADDR_MAX_LEN);
        cand->transport.port = host_comp->addr.port;
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
        cand->local_pref = host_comp->local_pref;
        cand->priority = ice_utils_compute_candidate_priority(cand);

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

    /** initialize the component list */
    for (i = 0; i < src->num_comp; i++)
    {
        dest->media_comps[i].comp_id = src->host_cands[i].comp_id;
        dest->media_comps[i].keepalive_timer = NULL;
        dest->media_comps[i].np = NULL;
    }

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

            /** Note: 
             * check for same stun server and same host. As per existing
             * API, all the media streams for a session share the same
             * STUN server. Hence not validating the stun server here ...
             */
            if ((cand2->type == cand1->type) &&
                (ice_utils_host_compare(cand2->base->transport.ip_addr, 
                                        cand1->base->transport.ip_addr, 
                                        cand1->transport.type) == true) &&
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

            stun_snprintf((char *)cand1->foundation, 
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



uint32_t ice_utils_get_conn_check_timer_duration(ice_media_stream_t *media)
{
    uint32_t i, num_active_checklists;
    ice_session_t *session = media->ice_session;

    num_active_checklists = 0;

    /**
     * The connectivity check timer duration is computed as equal to
     * [Ta * N] seconds, where N is the number of active check lists
     */
    for (i = 0; i < ICE_MAX_MEDIA_STREAMS; i++)
    {
        if (session->aps_media_streams[i] && 
            ((session->aps_media_streams[i]->state == ICE_MEDIA_CC_RUNNING) ||
             (session->aps_media_streams[i]->state == ICE_MEDIA_NOMINATING)))
            num_active_checklists++;
    }

    return (num_active_checklists * TA_VAL_FOR_CHECKS);
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
            (ice_utils_host_compare(cand->transport.ip_addr, 
                                src->ip_addr, cand->transport.type) == true))
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



handle ice_utils_get_turn_session_for_transport_param(
                    ice_media_stream_t *media, handle transport_param)
{
    ice_candidate_t *cand = 
        ice_utils_get_local_cand_for_transport_param(media, transport_param);

    if(cand == NULL) return cand;

    /** fixme: is there a better way! */
    return media->h_turn_sessions[cand->comp_id - 1];
}



bool_t ice_media_utils_have_nominated_list(ice_media_stream_t *media)
{
    uint32_t i;
    bool_t rtp_valid, rtcp_valid;
    ice_cand_pair_t *cp;

    rtp_valid = rtcp_valid = false;
    
    ICE_LOG(LOG_SEV_DEBUG, 
            "[ICE MEDIA] Checking for nominated candidate pairs in "\
            "the media %p.", media);

    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        cp = &media->ah_cand_pairs[i];
        if (cp->local == NULL) continue;

        if (cp->nominated == false) continue;

        if (cp->local->comp_id == RTP_COMPONENT_ID)
            rtp_valid = true;
        else if (cp->local->comp_id == RTCP_COMPONENT_ID)
            rtcp_valid = true;
    }

    if (rtp_valid == true)
    {
        ICE_LOG(LOG_SEV_DEBUG, "RTP is nominated");
    }

    if (rtcp_valid == true)
    {
        ICE_LOG(LOG_SEV_DEBUG, "RTCP is nominated");
    }

    if ((rtp_valid == true) && (media->num_peer_comp == 1))
    {
        ICE_LOG(LOG_SEV_INFO,
                "[ICE MEDIA] Number of components for this media %p is %d. "\
                "And nominated candidate pairs are available for each of the "\
                "component", media, media->num_peer_comp);
        return true;
    }

    if ((rtp_valid == true) && (rtcp_valid == true))
    {
        ICE_LOG(LOG_SEV_INFO,
                "[ICE MEDIA] Number of components for this media %p is %d. "\
                "And nominated candidate pairs are available for each of "\
                "the components", media, media->num_peer_comp);
        return true;
    }
    else 
    {
        ICE_LOG(LOG_SEV_INFO,
                "[ICE MEDIA] Number of components for this media %p is %d. "\
                "And nominated candidate pairs are NOT YET available for "\
                "each of the components", media, media->num_peer_comp);
        return false;
    }
}



int32_t ice_media_utils_copy_selected_pair(ice_media_stream_t *media)
{
    uint32_t i;
    ice_cand_pair_t *valid_cp, *backup_cp;

    for (i = 0; i < ICE_MAX_COMPONENTS; i++)
    {
        valid_cp = media->media_comps[i].np;
        backup_cp = &media->ah_prev_sel_pair[i];

        stun_memcpy(backup_cp, valid_cp, sizeof(ice_cand_pair_t));
    }

    return STUN_OK;
}



int32_t ice_utils_get_session_state_change_event(
                    ice_session_t *session, ice_state_t *event)
{
    int32_t status = STUN_OK;

    switch(session->state)
    {
        case ICE_SES_GATHERED: 
            *event = ICE_GATHERED;
            break;

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
        case ICE_MEDIA_GATHERED:
            *event = ICE_GATHERED;
            break;

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
        case ICE_MEDIA_GATHERING:
        case ICE_MEDIA_FROZEN:
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

    if ((status == STUN_OK) && (media->ice_session) &&
        (media->ice_session->instance) && 
        (media->ice_session->instance->media_state_event_cb))
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
        cand_pair = &media->ah_cand_pairs[i];
        if (cand_pair->local == NULL) continue;
        if (cand_pair->valid_pair == false) continue;

        if (j >= ICE_MAX_VALID_LIST_PAIRS) break;
        valid_pair = &valid_pairs->pairs[j];

        valid_pair->nominated = cand_pair->nominated;

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

        j += 1;
    }

    valid_pairs->num_valid = j;
    valid_pairs->h_media = (handle) media;

    return STUN_OK;
}



int32_t ice_media_utils_get_nominated_list(ice_media_stream_t *media, 
                                            ice_media_valid_pairs_t *nom_pairs)
{
    int32_t i, j;
    ice_cand_pair_t *comp_np;
    ice_component_t *comp;
    ice_valid_pair_t *vp;

    for (i = 0, j = 0 ; i < ICE_MAX_COMPONENTS; i++)
    {
        comp = &media->media_comps[i];
        if (comp->np == NULL) continue;

        comp_np = comp->np;

        if (j >= ICE_MAX_VALID_LIST_PAIRS) break;
        vp = &nom_pairs->pairs[j];

        vp->nominated = comp_np->nominated;

        vp->comp_id = comp_np->local->comp_id;

        
        vp->local.host_type = comp_np->local->transport.type;
        stun_strncpy((char *)vp->local.ip_addr, 
                    (char *)comp_np->local->transport.ip_addr, 
                    ICE_IP_ADDR_MAX_LEN - 1);
        vp->local.port = comp_np->local->transport.port;


        vp->peer.host_type = comp_np->remote->transport.type;
        stun_strncpy((char *)vp->peer.ip_addr, 
                        (char *)comp_np->remote->transport.ip_addr,
                        ICE_IP_ADDR_MAX_LEN - 1);
        vp->peer.port = comp_np->remote->transport.port;

        j += 1;
    }

    nom_pairs->num_valid = j;

    return STUN_OK;
}




int32_t ice_utils_determine_session_state(ice_session_t *session)
{
    int32_t status = STUN_OK, index;
    ice_media_stream_state_t lowest_state = ICE_MEDIA_IDLE;
    ice_session_state_t new_session_state;
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

        if(media->state > lowest_state)
            lowest_state = media->state;
    }

    ICE_LOG(LOG_SEV_DEBUG, 
        "The lowest state across all media streams is %d.", lowest_state);

    switch(lowest_state)
    {
        case ICE_MEDIA_IDLE:
            new_session_state = ICE_SES_IDLE;
            break;

        case ICE_MEDIA_GATHERING:
            new_session_state = ICE_SES_GATHERING;
            break;

        case ICE_MEDIA_GATHERED:
            new_session_state = ICE_SES_GATHERED;
            break;

        case ICE_MEDIA_FROZEN:
        case ICE_MEDIA_CC_RUNNING:
            new_session_state = ICE_SES_CC_RUNNING;
            break;

        case ICE_MEDIA_CC_COMPLETED:
            new_session_state = ICE_SES_CC_COMPLETED;
            //new_session_state = ICE_SES_NOMINATING;
            //new_session_state = ICE_SES_ACTIVE;
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
    return STUN_OK;
}


int32_t ice_utils_validate_turn_session_handle(
            ice_media_stream_t *media, handle h_turn_session, uint32_t *comp_id)
{
    int32_t i;

    for (i = 0; i < ICE_MAX_COMPONENTS; i++)
    {
        if (media->h_turn_sessions[i] == h_turn_session)
        {
            *comp_id = i+1;
            break;
        }
    }

    if (i == ICE_MAX_COMPONENTS)
    {
        /** we dont have this session handle? */
        ICE_LOG(LOG_SEV_DEBUG, 
                "Invalid turn session handle for this media, ignoring ...");
        return STUN_INVALID_PARAMS;
    }

    return STUN_OK;
}



int32_t ice_utils_validate_bind_session_handle(
            ice_media_stream_t *media, handle h_bind_session, uint32_t *comp_id)
{
    int32_t i;

    for (i = 0; i < ICE_MAX_COMPONENTS; i++)
    {
        if (media->h_bind_sessions[i] == h_bind_session)
        {
            *comp_id = i+1;
            break;
        }
    }

    if (i == ICE_MAX_COMPONENTS)
    {
        /** we dont have this session handle? */
        ICE_LOG(LOG_SEV_DEBUG, 
                "Invalid bind session handle for this media, ignoring ...");
        return STUN_INVALID_PARAMS;
    }

    return STUN_OK;
}



int32_t ice_utils_get_free_local_candidate(
                        ice_media_stream_t *media, ice_candidate_t **cand)
{
    int32_t i;

    for (i = 0; i < ICE_CANDIDATES_MAX_SIZE; i++)
        if (media->as_local_cands[i].type == ICE_CAND_TYPE_INVALID)
        {
            *cand = &media->as_local_cands[i];
            break;
        }

    if (i == ICE_CANDIDATES_MAX_SIZE)
    {
        ICE_LOG(LOG_SEV_DEBUG, 
                "Local candidates exceeded limit, no more slots left ...");
        *cand = NULL;
        return STUN_NO_RESOURCE;
    } 

    return STUN_OK;
}



int32_t ice_utils_copy_gathered_candidate_info(ice_candidate_t *cand, 
                                stun_inet_addr_t *alloc_addr, 
                                ice_cand_type_t cand_type, uint32_t comp_id,
                                ice_candidate_t *base_cand, bool_t def_cand)
{
    stun_memcpy(cand->transport.ip_addr, 
                        alloc_addr->ip_addr, ICE_IP_ADDR_MAX_LEN);
    cand->transport.port = alloc_addr->port;
    cand->transport.protocol = ICE_TRANSPORT_UDP;

    cand->type = cand_type;
    cand->comp_id = comp_id;

    cand->base = base_cand;
    cand->default_cand = def_cand;
    cand->transport_param = base_cand->transport_param;
    cand->local_pref = base_cand->local_pref;

    cand->priority = ice_utils_compute_candidate_priority(cand);

    return STUN_OK;
}



int32_t ice_utils_copy_turn_gathered_candidates(
        ice_media_stream_t *media, ice_int_params_t *param, uint32_t comp_id)
{
    int32_t status;
    ice_candidate_t *base_cand, *cand = NULL;
    turn_session_alloc_info_t alloc_info = {{0}, {0}};

    status = turn_session_get_allocation_info(param->h_inst, 
                                            param->h_session, &alloc_info);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_DEBUG, 
            "Unable to get allocation information from TURN %d ...", status);
        return status;
    }

    /** get the base candidate for this component */
    base_cand = ice_media_utils_get_base_cand_for_comp_id(media, comp_id);
    if (base_cand == NULL)
    {
        ICE_LOG(LOG_SEV_ERROR, "Unable to find base candidate for"\
               " component id [%d]", comp_id);
        return STUN_INT_ERROR;
    }

    status = ice_utils_get_free_local_candidate(media, &cand);
    if (status == STUN_NO_RESOURCE) return status;

    /** copy server reflexive candidate information */
    ice_utils_copy_gathered_candidate_info(cand, 
                            &alloc_info.mapped_addr, ICE_CAND_TYPE_SRFLX, 
                            comp_id, base_cand, false);

    status = ice_utils_get_free_local_candidate(media, &cand);
    if (status == STUN_NO_RESOURCE) return status;

    /** 
     * If a relayed candidate is identical to a host candidate (which can 
     * happen in rare cases), the relayed candidate must be discarded. 
     */
    if (ice_utils_host_compare(base_cand->transport.ip_addr, 
                               alloc_info.relay_addr.ip_addr, 
                               base_cand->transport.type) == true)
    {
        ICE_LOG(LOG_SEV_DEBUG, "Discovered relayed candidate is "\
                "identical to host candidate. Hence ignoring...");
        return STUN_OK;
    }

    /** copy relay candidate information */
    ice_utils_copy_gathered_candidate_info(cand, 
                            &alloc_info.relay_addr, ICE_CAND_TYPE_RELAYED, 
                            comp_id, base_cand, true);

    /**
     * Sec 4.1.4 of RFC 5245 - choosing default candidates
     * It is recommended that default candidates be chosen based on the
     * likelihood of those candidates to work with the peer that is being
     * contacted. It is RECOMMENDED that the default candidates are the
     * relayed candidates (if relayed candidates are available), server
     * reflexive candidates (if server reflexive candidates are available),
     * and finally host candidates.
     */
    base_cand->default_cand = false;

    return STUN_OK;
}




int32_t ice_utils_copy_stun_gathered_candidates(ice_media_stream_t *media, 
        handle h_bind_inst, handle h_bind_session, ice_rx_stun_pkt_t *rx_pkt)
{
    int32_t status;
    stun_inet_addr_t mapped_addr;
    ice_candidate_t *base_cand, *cand = NULL;

    status = stun_binding_session_get_xor_mapped_address(
                        h_bind_inst, h_bind_session, &mapped_addr);
    if (status != STUN_OK)
    {
#ifdef MB_SUPPORT_3489
        status = stun_binding_session_get_mapped_address(
                        h_bind_inst, h_bind_session, &mapped_addr);

        if (status != STUN_OK)
        {
#endif
            ICE_LOG(LOG_SEV_ERROR, 
                "unable to get mapped address. Returned error: %d", status);
            return STUN_NOT_FOUND;
#ifdef MB_SUPPORT_3489
        }
#endif
    }

    /** get the base candidate for this component */
    base_cand = 
        ice_media_utils_get_host_cand_for_transport_param(media, rx_pkt);
    if (base_cand == NULL)
    {
        ICE_LOG(LOG_SEV_ERROR, "Unable to find base candidate for"\
               " received STUN BINDING response while gathering candidates");
        return STUN_INT_ERROR;
    }

    status = ice_utils_get_free_local_candidate(media, &cand);
    if (status == STUN_NO_RESOURCE) return status;

    /** copy server reflexive candidate information */
    ice_utils_copy_gathered_candidate_info(cand, 
                            &mapped_addr, ICE_CAND_TYPE_SRFLX, 
                            base_cand->comp_id, base_cand, true);

    /**
     * Sec 4.1.4 of RFC 5245 - choosing default candidates
     * It is recommended that default candidates be chosen based on the
     * likelihood of those candidates to work with the peer that is being
     * contacted. It is RECOMMENDED that the default candidates are the
     * relayed candidates (if relayed candidates are available), server
     * reflexive candidates (if server reflexive candidates are available),
     * and finally host candidates.
     */
    base_cand->default_cand = false;

    return STUN_OK;
}



int32_t ice_media_utils_start_check_list_timer(ice_media_stream_t *media)
{
    int32_t status;
    uint32_t cc_timer_value;
    ice_timer_params_t *timer = media->checklist_timer;

    if(timer == NULL)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[ICE] Media conn check timer param is NULL");
        return STUN_INT_ERROR;
    }

    /** 
     * start the check timer. This is a common timer 
     * for both ordinary and triggered checks.
     */
    cc_timer_value = ice_utils_get_conn_check_timer_duration(media);

    timer->h_instance = media->ice_session->instance;
    timer->h_session = media->ice_session;
    timer->h_media = media;
    timer->arg = NULL;
    timer->type = ICE_CHECK_LIST_TIMER;

    timer->timer_id = media->ice_session->instance->start_timer_cb(
                                    cc_timer_value, media->checklist_timer);
    if (timer->timer_id)
    {
        ICE_LOG(LOG_SEV_DEBUG, 
                "[ICE] Started check list timer for %d msec for media %p. "\
                "timer id %p", cc_timer_value, media, timer->timer_id);
        status =  STUN_OK;
    }
    else
    {
        ICE_LOG(LOG_SEV_DEBUG, 
                "[ICE] Starting of check list timer for %d msec for media %p "\
                "failed", cc_timer_value, media);
        status = STUN_INT_ERROR;
    }

    return status;
}



int32_t ice_media_utils_stop_check_list_timer(ice_media_stream_t *media)
{
    int32_t status = STUN_OK;

    if (media->checklist_timer == NULL) return status;
    if (media->checklist_timer->timer_id == NULL) return status;

    status = media->ice_session->instance->stop_timer_cb(
                                        media->checklist_timer->timer_id);
    if (status == STUN_OK) media->checklist_timer->timer_id = NULL;

    return status;
}



int32_t ice_media_utils_start_nomination_timer(ice_media_stream_t *media)
{
    int32_t status;
    ice_timer_params_t *timer = media->nomination_timer;

    if(timer == NULL)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[ICE] Media conn check nomination timer param is NULL");
        return STUN_INT_ERROR;
    }

    timer->h_instance = media->ice_session->instance;
    timer->h_session = media->ice_session;
    timer->h_media = media;
    timer->arg = NULL;
    timer->type = ICE_NOMINATION_TIMER;

    timer->timer_id = media->ice_session->instance->start_timer_cb(
                        ICE_CC_NOMINATION_TIMER_VALUE, media->nomination_timer);
    if (timer->timer_id)
    {
        ICE_LOG(LOG_SEV_DEBUG, 
                "[ICE] Started nomination timer for %d msec for media %p. "\
                "timer id %p", ICE_CC_NOMINATION_TIMER_VALUE, media, 
                timer->timer_id);
        status =  STUN_OK;
    }
    else
    {
        ICE_LOG(LOG_SEV_DEBUG, 
                "[ICE] Starting of nomination timer for %d msec for media %p "\
                "failed", ICE_CC_NOMINATION_TIMER_VALUE, media);
        status = STUN_INT_ERROR;
    }

    return status;
}



int32_t ice_media_utils_stop_nomination_timer(ice_media_stream_t *media)
{
    int32_t status = STUN_OK;

    if (media->nomination_timer == NULL) return status;
    if (media->nomination_timer->timer_id == NULL) return status;

    status = media->ice_session->instance->stop_timer_cb(
                                        media->nomination_timer->timer_id);
    if (status == STUN_OK) media->nomination_timer->timer_id = NULL;

    return status;
}



int32_t ice_utils_start_keep_alive_timer_for_comp(
                        ice_media_stream_t *media, uint32_t comp_id)
{
    int32_t status, i;
    ice_component_t *comp = NULL;
    ice_timer_params_t *timer = NULL;

    for (i = 0; i < ICE_MAX_COMPONENTS; i++)
    {
        if (media->media_comps[i].comp_id == comp_id)
        {
            comp = &media->media_comps[i];
            break;
        }
    }

    if (comp == NULL)
    {
        /** this is sad */
        ICE_LOG(LOG_SEV_ERROR, 
                "[ICE] Unknown media component ID. So not starting "\
                "the keepalive timer");
        return STUN_INVALID_PARAMS;
    }

    if(comp->keepalive_timer == NULL)
    {
        comp->keepalive_timer = (ice_timer_params_t *) 
                            stun_calloc (1, sizeof(ice_timer_params_t));
        if (comp->keepalive_timer == NULL)
        {
            ICE_LOG (LOG_SEV_ERROR, 
                    "[ICE MEDIA] Memory allocation failed for ICE "\
                    "component keep alive timer");
            return STUN_NO_RESOURCE;
        }
    }

    timer = comp->keepalive_timer;
    timer->timer_id = 0;

    timer->h_instance = media->ice_session->instance;
    timer->h_session = media->ice_session;
    timer->h_media = media;
    timer->arg = (handle) comp_id;
    timer->type = ICE_KEEP_ALIVE_TIMER;

    timer->timer_id = media->ice_session->instance->start_timer_cb(
                        ICE_KEEP_ALIVE_TIMER_VALUE, comp->keepalive_timer);
    if (timer->timer_id)
    {
        ICE_LOG(LOG_SEV_DEBUG, 
                "[ICE] Started ICE Keep Alive timer for %d msec for media %p"\
                " and comp id %d. timer id is %p", 
                ICE_KEEP_ALIVE_TIMER_VALUE, media, comp_id, timer->timer_id);
        status =  STUN_OK;
    }
    else
    {
        ICE_LOG(LOG_SEV_DEBUG, 
                "[ICE] Starting of ICE Keep Alive timer for %d msec for media "\
                "%p and comp id %d failed", ICE_KEEP_ALIVE_TIMER_VALUE, 
                media, comp_id);
        status = STUN_INT_ERROR;
    }

    return status;
}



int32_t ice_utils_stop_keep_alive_timer_for_comp(
                            ice_media_stream_t *media, uint32_t comp_id)
{
    int32_t i, status = STUN_OK;
    ice_component_t *comp = NULL;

    for (i = 0; i < ICE_MAX_COMPONENTS; i++)
    {
        if (media->media_comps[i].comp_id == comp_id)
        {
            comp = &media->media_comps[i];
            break;
        }
    }

    if (comp == NULL)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[ICE] Unknown media component ID. Unable to stop the "\
                "keepalive timer for the given comp id %d", comp_id);
        return STUN_NOT_FOUND;
    }


    if (comp->keepalive_timer == NULL) return status;
    if (comp->keepalive_timer->timer_id == NULL) return status;

    status = media->ice_session->instance->stop_timer_cb(
                                        comp->keepalive_timer->timer_id);
    if (status == STUN_OK) comp->keepalive_timer->timer_id = NULL;

    return status;
}




int32_t ice_utils_find_cand_pair_for_conn_check_session(
        ice_media_stream_t *media, handle h_conn_check, ice_cand_pair_t **cp)
{
    int32_t i;
    ice_cand_pair_t *pair;

    ICE_LOG(LOG_SEV_INFO, "Searching for "\
            "connectivity check session handle [%ld]", h_conn_check);

    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        pair = &media->ah_cand_pairs[i];
        if (!pair->local) continue;

        ICE_LOG(LOG_SEV_INFO, "[%d]: State: [%s] [%ld] [%ld] [%s:%d]", 
                i, cand_pair_states[pair->state], pair->h_cc_session, 
                pair->h_cc_cancel, pair->remote->transport.ip_addr, 
                pair->remote->transport.port);

        if ((pair->h_cc_session == h_conn_check) || (pair->h_cc_cancel == h_conn_check))
        {
            *cp = pair;
            return STUN_OK;
        }
    }

    return STUN_NOT_FOUND;
}



int32_t ice_utils_search_local_candidates(ice_media_stream_t *media, 
                        stun_inet_addr_t *src, ice_candidate_t **found_cand)
{
    int32_t i;
    ice_candidate_t *local_cand;

    /** 
     * check if the mapped address from the connectivity 
     * check matches any of the local candidate 
     */
    for (i = 0; i < ICE_CANDIDATES_MAX_SIZE; i++)
    {
        local_cand = &media->as_local_cands[i];
        if(local_cand->type == ICE_CAND_TYPE_INVALID) continue;

        /** not checking the transport protocol, UDP is assumed. */
        if((local_cand->transport.type == src->host_type) &&
           (local_cand->transport.port == src->port) &&
           (ice_utils_host_compare(local_cand->transport.ip_addr, 
                        src->ip_addr, local_cand->transport.type) == true))
        {
            /** OK, this candidate is already part of the local candidates */
            ICE_LOG(LOG_SEV_INFO, 
                    "[ICE] The mapped address learned from the conn check is "\
                    "already part of the local candidate list for media %p", 
                    media);
            *found_cand = local_cand;
            return STUN_OK;
        }
    }

    return STUN_NOT_FOUND;
}



int32_t ice_utils_add_local_peer_reflexive_candidate(ice_cand_pair_t *cp, 
                    stun_inet_addr_t *src, ice_candidate_t **new_prflx)
{
    int32_t i;
    ice_media_stream_t *media = cp->media;
    ice_candidate_t *prflx_cand;

    /** RFC 5245 sec 7.1.2.2.1 - check if peer reflexive candidate */

    for (i = 0; i < ICE_CANDIDATES_MAX_SIZE; i++)
        if(media->as_local_cands[i].type == ICE_CAND_TYPE_INVALID) break;

    if (i == ICE_CANDIDATES_MAX_SIZE)
    {
        ICE_LOG(LOG_SEV_ERROR,
                "No more free local candidates available to add the peer "\
                "reflexive candidate. Reached the maximum configured limit.");

        return STUN_NO_RESOURCE;
    }

    /** 
     * the mapped address is not part of the local candidate list.
     * This is a candidate - a peer reflexive candidate.
     */
    prflx_cand = &media->as_local_cands[i];

    /** transport params */
    prflx_cand->transport.type = src->host_type;
    memcpy(prflx_cand->transport.ip_addr, 
                        src->ip_addr, ICE_IP_ADDR_MAX_LEN);
    prflx_cand->transport.port = src->port;

    /** Note: protocol is assumed to be always UDP */
    prflx_cand->transport.protocol = ICE_TRANSPORT_UDP;

    /** component id */
    prflx_cand->comp_id = cp->local->comp_id;

    /** 
     * copy the application transport handle. This handle is 
     * valid only to host candidate types.
     * revisit -- should this be moved to media component level?
     */
    prflx_cand->transport_param = cp->local->transport_param;

    prflx_cand->type = ICE_CAND_TYPE_PRFLX;

    prflx_cand->default_cand = false;
    prflx_cand->base = cp->local;
    prflx_cand->local_pref = cp->local->local_pref;

    /** calculation of priority is bit different from spec - revisit? */
    prflx_cand->priority = 
        ice_utils_compute_peer_reflexive_candidate_priority(prflx_cand);

    /** TODO = foundation */
    stun_strncpy((char *)prflx_cand->foundation, "4", 1);

    *new_prflx = prflx_cand;

    return STUN_OK;
}



int32_t ice_utils_install_turn_permissions(ice_media_stream_t *media)
{
    int32_t i, status;
    ice_cand_pair_t *cp;
    stun_inet_addr_t addr;
    handle h_turn_session;
    handle h_turn_inst = media->ice_session->instance->h_turn_inst;

    /**
     * ICE RFC 5245 - 7.1.1.  Creating Permissions for Relayed Candidates
     *
     * If the connectivity check is being sent using a relayed local
     * candidate, the client MUST create a permission first if it has not
     * already created one previously.
     */
    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        cp = &media->ah_cand_pairs[i];

        if (!cp->local) continue;
        if(cp->local->type != ICE_CAND_TYPE_RELAYED) continue;

        addr.host_type = cp->remote->transport.type;
        addr.port = cp->remote->transport.port;
        stun_memcpy(addr.ip_addr, 
                cp->remote->transport.ip_addr, ICE_IP_ADDR_MAX_LEN);

        /** note: better way to arrive at this? */
        h_turn_session = media->h_turn_sessions[cp->local->comp_id - 1];

        status = turn_session_add_peer_address(h_turn_inst, 
                                                    h_turn_session, &addr);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                    "Installation of permission for peer address failed");
            return status;
        }
    }

    for (i = 0; i < ICE_MAX_COMPONENTS; i++)
    {
        if (media->h_turn_sessions[i] == NULL) continue;

        status = turn_session_create_permissions(h_turn_inst, 
                        media->h_turn_sessions[i], TURN_CREATE_PERMISSION);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                    "TURN API for Creation of permission failed");
            break;
        }
    }

    return status;
}



int32_t ice_media_utils_update_cand_pair_states(
                            ice_media_stream_t *media, ice_cand_pair_t *cur_cp)
{
    ice_cand_pair_t *cp;
    int32_t i, status = STUN_INT_ERROR;

    /**
     * RFC 5245 Sec 7.1.3.2.3 Updating Pair States
     * - The agent changes the states for all other Frozen pairs 
     *   for the same media stream and same foundation to Waiting.
     */
    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        cp = &media->ah_cand_pairs[i];
        if (cp->local == NULL) continue;

        if (cp == cur_cp) continue;
        if (cp->state != ICE_CP_FROZEN) continue;

        if ((stun_strncmp((char *)cp->local->foundation, 
                          (char *)cur_cp->local->foundation, 
                          ICE_FOUNDATION_MAX_LEN) == 0) &&
            (stun_strncmp((char *)cp->remote->foundation, 
                          (char *)cur_cp->remote->foundation,
                          ICE_FOUNDATION_MAX_LEN) == 0))
        {
            /** foundation of these both candidate pairs match */
            status = ice_cand_pair_fsm_inject_msg(
                                    cp, ICE_CP_EVENT_UNFREEZE, NULL);
            if (status != STUN_OK)
            {
                ICE_LOG(LOG_SEV_ERROR,
                        "[ICE] Unfreezing of the candidate pair failed");
                return status;
            }
        }
    }

    return status;
}



int32_t ice_utils_detect_repair_role_conflicts(
        ice_media_stream_t *media, conn_check_result_t *check_result)
{
    /** sec 7.2.1.1 of RFC 5245 - Detecting and repairing role conflicts */

    return STUN_OK;
}


ice_cand_pair_t *ice_utils_lookup_pair_in_checklist(
                                                    ice_media_stream_t *media,
                                                    ice_candidate_t *local,
                                                    ice_candidate_t *remote)
{
    int32_t i;
    ice_cand_pair_t *cp;

    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        cp = &media->ah_cand_pairs[i];

        if ((cp->local == local) && (cp->remote == remote))
            return cp;
    }

    return NULL;
}



int32_t ice_utils_add_to_triggered_check_queue(
                            ice_media_stream_t *media, ice_cand_pair_t *cp)
{
    int32_t status;
    ice_trigger_check_node_t *elem, *iter, *lag;
    
    iter = media->trig_check_list;
    lag = NULL;

    /** make sure this candidate pair is not already on the triggered list */
    while (iter != NULL)
    {
        if (iter->cp == cp)
        {
            ICE_LOG(LOG_SEV_INFO,
                    "[ICE MEDIA] Queueing the incoming connectivity check in "\
                    "Triggered Q, but found that this pair %p is already on "\
                    "the Triggered Q. Hence not adding to Q now", cp);
            
            return STUN_OK;
        }

        lag = iter;
        iter = iter->next;
    }

    /** Always add the candidate pair at the end */
    /** TODO - Better to make the triggered list as a queue so that adding and removing is O(1)? */

    elem = (ice_trigger_check_node_t *) 
                        stun_calloc(1, sizeof(ice_trigger_check_node_t));
    if (elem == NULL) return STUN_MEM_ERROR;
    elem->cp = cp;
    elem->next = NULL;

    if (lag)
        lag->next = elem;
    else
        media->trig_check_list = elem;

    ICE_LOG(LOG_SEV_INFO, 
            "[ICE MEDIA] Queued the candidate pair %p in the triggered Q", cp);

    /** start the check list timer if stopped */
    if ((media->checklist_timer) && (media->checklist_timer->timer_id == 0))
    {
        status = ice_media_utils_start_check_list_timer(media);
    }

    return STUN_OK;
}




int32_t ice_utils_search_remote_candidates(ice_media_stream_t *media, 
                    stun_inet_addr_t *pkt_src, ice_candidate_t **found_cand)
{
    int32_t i;
    ice_candidate_t *rem_cand;

    /** 
     * check if the source address of the incoming connectivity check 
     * matches any of the remote candidates that we received in sdp answer.
     */
    for (i = 0; i < ICE_CANDIDATES_MAX_SIZE; i++)
    {
        rem_cand = &media->as_remote_cands[i];
        if(rem_cand->type == ICE_CAND_TYPE_INVALID) continue;

        /** not checking the transport protocol, UDP is assumed. */
        if((rem_cand->transport.type == pkt_src->host_type) &&
           (rem_cand->transport.port == pkt_src->port) &&
           (ice_utils_host_compare(rem_cand->transport.ip_addr, 
                 pkt_src->ip_addr, rem_cand->transport.type) == true))
        {
            /** OK, this candidate is already part of the remote candidates */
            ICE_LOG(LOG_SEV_INFO, 
                    "[ICE] The source address of the received incoming conn "\
                    "check request is already part of the remote candidate "\
                    "list for media %p", media);
            *found_cand = rem_cand;
            return STUN_OK;
        }
    }

    return STUN_NOT_FOUND;
}




int32_t ice_utils_add_to_ic_check_queue_without_answer(
                ice_media_stream_t *media, ice_candidate_t *local, 
                conn_check_result_t *check_info, stun_inet_addr_t *remote)
{
    int32_t i;
    ice_ic_check_t *ic_check;

    /** find a free slot */
    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
        if (media->ic_checks[i].local_cand == NULL) break;

    if (i == ICE_MAX_CANDIDATE_PAIRS)
    { 
        ICE_LOG(LOG_SEV_INFO,
                "[ICE MEDIA] Answer not yet received. But Queueing of the "\
                "incoming connectivity check failed since no more resource "\
                "available for queueing");

        return STUN_NO_RESOURCE;
    }

    ic_check = &media->ic_checks[i];

    ic_check->local_cand = local;
    stun_memcpy(&ic_check->peer_addr, remote, sizeof(stun_inet_addr_t));

    /** priority */
    ic_check->prflx_priority = check_info->priority;

    /** nominated status */
    ic_check->nominated = check_info->nominated;

    /** role */
    ic_check->controlling_role = check_info->controlling_role;

    media->ic_check_count++;

    ICE_LOG(LOG_SEV_INFO,
            "[ICE MEDIA] Answer not yet received, hence Queued the incoming "\
            "connectivity check at index %d. Total count %d", 
            i, media->ic_check_count);

    return STUN_OK;
}



int32_t ice_utils_process_pending_ic_checks(ice_media_stream_t *media)
{
    int32_t i, status;
    ice_ic_check_t *ic_check;
    ice_candidate_t *remote_cand;
    ice_cand_pair_t *cp;

    ICE_LOG(LOG_SEV_INFO,
            "[ICE] There are [%d] pending checks", media->ic_check_count);

    for (i = 0; i < media->ic_check_count; i++)
    {
        ic_check = &media->ic_checks[i];
        remote_cand = NULL;

        /**
         * RFC 5245 Sec 7.2.1.3 Learning Peer Reflexive Candidates
         */
        status = ice_utils_search_remote_candidates(media, 
                                            &ic_check->peer_addr, &remote_cand);
        if (status == STUN_NOT_FOUND)
        {
            /** Found a peer reflexive candidate */
            status = ice_utils_add_remote_peer_reflexive_candidate(media, 
                            &ic_check->peer_addr, ic_check->local_cand->comp_id,
                            ic_check->prflx_priority, &remote_cand);
            if (status != STUN_OK)
            {
                ICE_LOG(LOG_SEV_ERROR,
                        "[ICE] Unable to add new remote peer reflexive "\
                        "candidate - %d", status);
                continue;
            }

            ICE_LOG(LOG_SEV_WARNING,
                    "[ICE] Added a new remote peer reflexive candidate");
        }

        /**
         * RFC 5245 Sec 7.2.1.4 Triggered Checks
         * Look up in the media checklist if there exists a candidate 
         * pair already for the current local and remote candidates
         */
        cp = ice_utils_lookup_pair_in_checklist(
                                media, ic_check->local_cand, remote_cand);
        if (cp == NULL)
        {
            ICE_LOG(LOG_SEV_INFO, 
                    "[ICE] The pair is NOT already on the check list ...");

            /** 
             * add a new candidate pair and insert 
             * into the checklist based on  priority 
             */
            status = ice_media_utils_add_new_candidate_pair(
                                media, ic_check->local_cand, remote_cand, &cp);

            if (cp == NULL)
            {
                ICE_LOG(LOG_SEV_INFO, "[ICE] Pathetic! Fix me. CP is NULL ...");
            }

            /** set the state of this candidate pair to WAITING */
            status = ice_cand_pair_fsm_inject_msg(
                                    cp, ICE_CP_EVENT_UNFREEZE, NULL);

            /** The pair is enqueued into the triggered check queue */
            status = ice_utils_add_to_triggered_check_queue(media, cp);
        }
        else
        {
            ICE_LOG(LOG_SEV_INFO, 
                    "[ICE] The pair is already on the check list ...");

            /** check the current state of the pair */
            if ((cp->state == ICE_CP_FROZEN) || (cp->state == ICE_CP_WAITING))
            {
                status = ice_utils_add_to_triggered_check_queue(media, cp);
            }
            else if (cp->state == ICE_CP_INPROGRESS)
            {
                /**
                 * cancel the in-progress transaction. In addition, 
                 * create a new connectivity check for this pair by 
                 * enqueueing this pair in the triggered check queue. 
                 * Change the state of the candidate pair to Waiting 
                 * At this instance, this agent would not have started
                 * any connectivity checks.
                 */
            }
            else if (cp->state == ICE_CP_FAILED)
            {
                /** change the state to Waiting */
                status = ice_cand_pair_fsm_inject_msg(
                                        cp, ICE_CP_EVENT_UNFREEZE, NULL);

                /** add to triggered queue */
                status = ice_utils_add_to_triggered_check_queue(media, cp);
            }
            else if (cp->state == ICE_CP_SUCCEEDED)
            {
                /** do nothing */
            }
            else
            {
                ICE_LOG(LOG_SEV_CRITICAL,
                        "Unknown invalid candidate pair state %d", cp->state);
                return status;
            }
        }

        /**
         * If the connectivity check is still in progress or 
         * is yet to be intiiated, set the nominated flag status 
         * as decided by the peer who is in CONTROLLING mode.
         */
        if (media->ice_session->role == ICE_AGENT_ROLE_CONTROLLED)
            cp->nominated = ic_check->nominated;

        
        /**
         * RFC 5245 Sec 7.2.1.5 Updating the Nominated Flag
         */
        if ((ic_check->nominated == true) &&
            (media->ice_session->role == ICE_AGENT_ROLE_CONTROLLED))
        {
            /**
             * Typically at this stage when we have just received the remote
             * answer, and formed the check lists, all the candidate pairs
             * will be in FROZEN state.
             */
            if (cp->state == ICE_CP_SUCCEEDED)
            {
                /**
                 * If the state of the cached pair is succeeded, it means that the 
                 * incoming connectivity check from the peer had the USE-CANDIDATE
                 * attribute set and the peer has nominated the pair for the check.
                 * So update the nominated flag for this 
                 */
                if (cp->valid_pair == false)
                {
                    ICE_LOG(LOG_SEV_INFO,
                            "[ICE] Candidate pair connectivity check state is "\
                            "Succeeded. However the valid pair flag for this "\
                            "check is FALSE");

                    return STUN_INT_ERROR;
                }

                cp->nominated = ic_check->nominated;

                /** 
                 * This could conclude ICE processing for this media checklist
                 */
                status = ice_utils_update_media_checklist_state(media, cp);
            }
            else if (cp->state == ICE_CP_INPROGRESS)
            {
                ICE_LOG(LOG_SEV_INFO,
                        "This candidate pair check is still in progress.");

                /**
                 * The nominated flag for this candidate pair has been updated.
                 * When and if the check succeeds, the candidate pair will be
                 * added to the valid list and this flag will be reflected in
                 * the valid list
                 */
            }
            else
            {
                /** do nothing!!! */
            }
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

    /** RFC 5245 sec 7.1.2.2.1 - check if peer reflexive candidate */

    for (i = 0; i < ICE_CANDIDATES_MAX_SIZE; i++)
        if(media->as_remote_cands[i].type == ICE_CAND_TYPE_INVALID) break;

    if (i == ICE_CANDIDATES_MAX_SIZE)
    {
        ICE_LOG(LOG_SEV_ERROR,
                "No more free remote candidates available to add the peer "\
                "reflexive candidate. Reached the maximum configured limit.");

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



int32_t ice_media_utils_add_new_candidate_pair(ice_media_stream_t *media, 
        ice_candidate_t *local, ice_candidate_t *remote, ice_cand_pair_t **cp)
{
    int32_t i;
    ice_cand_pair_t *new_pair;

    /** find a free slot */
    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
        if (media->ah_cand_pairs[i].local == NULL) break;

    if (i == ICE_MAX_CANDIDATE_PAIRS)
    {
        ICE_LOG(LOG_SEV_ERROR,
                "[ICE] Exhausted the list of available candidate pairs "\
                "in the checklist for media %p. Hence adding of new "\
                "candidate pair failed", media);
        return STUN_NO_RESOURCE;
    }

    new_pair = &media->ah_cand_pairs[i];

    new_pair->local = local;
    new_pair->remote = remote;

    /** calculate pair priority? */
    ice_media_utils_compute_candidate_pair_priority(media, new_pair);

    new_pair->media = media;

    *cp = new_pair;

    return STUN_OK;
}



int32_t ice_utils_process_incoming_check(
                ice_media_stream_t *media, ice_candidate_t *local_cand, 
                ice_rx_stun_pkt_t *stun_pkt, conn_check_result_t *check_result)
{
    int32_t status;
    ice_candidate_t *remote_cand;
    ice_cand_pair_t *cp;


    /**
     * RFC 5245 Sec 7.2.1.3 Learning Peer Reflexive Candidates
     */
    status = ice_utils_search_remote_candidates(media, 
                                        &stun_pkt->src, &remote_cand);
    if (status == STUN_NOT_FOUND)
    {
        /** Found a peer reflexive candidate */
        status = ice_utils_add_remote_peer_reflexive_candidate(
                                    media, &stun_pkt->src, local_cand->comp_id, 
                                    check_result->priority, &remote_cand);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR,
                    "[ICE] Unable to add new remote peer reflexive "\
                    "candidate - %d", status);
            return status;
        }
    }

    /**
     * RFC 5245 Sec 7.2.1.4 Triggered Checks
     * Look up in the media checklist if there exists a candidate 
     * pair already for the current local and remote candidates
     */
    cp = ice_utils_lookup_pair_in_checklist(media, local_cand, remote_cand);
    if (cp == NULL)
    {
        ICE_LOG(LOG_SEV_INFO, 
                "[ICE] The pair is NOT already on the check list ...");

        /** 
         * add a new candidate pair and insert 
         * into the checklist based on priority 
         */
        status = ice_media_utils_add_new_candidate_pair(
                            media, local_cand, remote_cand, &cp);
        if (cp == NULL)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                    "[ICE] Unable to add new candidate pair");
            return status;
        }

        /** set the state of this candidate pair to WAITING */
        status = ice_cand_pair_fsm_inject_msg(
                                cp, ICE_CP_EVENT_UNFREEZE, NULL);

        /** The pair is enqueued into the triggered check queue */
        status = ice_utils_add_to_triggered_check_queue(media, cp);
    }
    else
    {
        ICE_LOG(LOG_SEV_INFO, 
                "[ICE] The pair is already on the check list ...");

        /** check the current state of the pair */
        if ((cp->state == ICE_CP_FROZEN) || (cp->state == ICE_CP_WAITING))
        {
            status = ice_utils_add_to_triggered_check_queue(media, cp);
        }
        else if (cp->state == ICE_CP_INPROGRESS)
        {
            /** 
             * cancel the in-progress transaction. In addition, 
             * create a new connectivity check for this pair by 
             * enqueueing this pair in the triggered check queue. 
             * Change the state of the candidate pair to Waiting 
             */
            cp->h_cc_cancel = cp->h_cc_session;
            cp->h_cc_session = NULL;
            conn_check_cancel_session(
                    media->ice_session->instance->h_cc_inst, cp->h_cc_cancel);

            status = ice_cand_pair_fsm_inject_msg(
                                    cp, ICE_CP_EVENT_UNFREEZE, NULL);

            status = ice_utils_add_to_triggered_check_queue(media, cp);
        }
        else if (cp->state == ICE_CP_FAILED)
        {
            /** change the state to Waiting */
            status = ice_cand_pair_fsm_inject_msg(
                                    cp, ICE_CP_EVENT_UNFREEZE, NULL);

            /** add to triggered queue */
            status = ice_utils_add_to_triggered_check_queue(media, cp);
        }
        else if (cp->state == ICE_CP_SUCCEEDED)
        {
            /** do nothing */
        }
        else
        {
            ICE_LOG(LOG_SEV_CRITICAL,
                    "[ICE] Unknown invalid candidate pair state %d", cp->state);
            return status;
        }
    }

    /**
     * RFC 5245 Sec 7.2.1.5 Updating the Nominated Flag
     */
    if ((check_result->nominated == true) &&
        (media->ice_session->role == ICE_AGENT_ROLE_CONTROLLED))
    {
        /**
         * If the state of the pair is Succeeded, it means that the 
         * check generated by this pair produced a successful response.
         * This would have caused the agent to construct a valid pair 
         * when that success response was received. The agent now sets 
         * the nominated flag in the valid pair to true.
         */
        if (cp->state == ICE_CP_SUCCEEDED)
        {
            /** check if this pair is valid */
            if (cp->valid_pair == false)
            {
                ice_cand_pair_t *vp = NULL;

                /**
                 * If this connectivity check has not been validated by 
                 * the controlled agent, then the check might have 
                 * resulted in the creation of another valid candidate 
                 * pair. This happens when the controlled agent is behind
                 * a NAT and the server reflexive candidate is chosen. The
                 * ice spec does not explicitly state this behavior.
                 */ 
                ICE_LOG(LOG_SEV_INFO,
                        "[ICE] Candidate pair connectivity check state is "\
                        "Succeeded. However the valid pair flag for this "\
                        "check is FALSE. Hence search for the associated "\
                        "pair in the valid list");

                vp = ice_media_utils_get_associated_valid_pair_for_cand_pair(media, cp);

                if (vp)
                {
                    ICE_LOG(LOG_SEV_INFO,
                            "[ICE] CONTROLLED ROLE - Associated valid pair"\
                            " found for the nominated check request "\
                            "received from peer. Hence choosing the "\
                            "validated pair as the nominated pair");
                    cp = vp;
                }
                else
                {
                    /** This should never happen! */
                    ICE_LOG(LOG_SEV_CRITICAL,
                            "[ICE] No validated pair found for the "\
                            "incoming nominated connectivity check in the"\
                            "valid list. CONTROLLED ROLE");
                    return status;
                }
            }

            cp->nominated = true;

            ice_media_utils_update_nominated_pair_for_comp(media, cp);

            status = ice_utils_start_keep_alive_timer_for_comp(
                                                media, cp->local->comp_id);
            if (status != STUN_OK)
            {
                /** just log the error */
                ICE_LOG(LOG_SEV_CRITICAL,
                        "[ICE MEDIA] Starting of the media keep alive timer "\
                        "failed for media %p and component ID %d", 
                        media, cp->local->comp_id);
            }

            /** This could conclude ICE processing for this media checklist */
            status = ice_utils_update_media_checklist_state(media, cp);
        }
        else if (cp->state == ICE_CP_INPROGRESS)
        {
            ICE_LOG(LOG_SEV_INFO,
                    "This candidate pair check is still in progress.");

            /** 
             * setting this flag indicates that the connectivity check for 
             * this candidate pair has been nominated by the peer which 
             * is in CONTROLLING role. Once and if the check succeeds for this
             * pair and when the pair is added to the valid list, this flag
             * will decide if the valid pair is nominated one or not.
             */
            cp->nominated = true;
        }
        else
        {
            /** do nothing!!! */
        }
    }


    return STUN_OK;
}



ice_cand_pair_t *ice_utils_search_cand_pair_in_valid_pair_list(
                                ice_media_stream_t *media, ice_cand_pair_t *cp)
{
    int32_t i;
    ice_cand_pair_t *pair;

    for (i = 0; i < ICE_CANDIDATES_MAX_SIZE; i++)
    {
        pair = &media->ah_cand_pairs[i];
        if (pair->local == NULL) continue;
        if (pair->valid_pair == false) continue;

        if((pair->local == cp->local) &&
           (pair->remote == cp->remote))
        {
            /** OK, we nailed him! */
            ICE_LOG(LOG_SEV_INFO, 
                    "[ICE] Found an entry in the valid list for media %p "\
                    "corresponding to given candidate pair", media);
            return pair;
        }
    }

    ICE_LOG(LOG_SEV_ERROR, 
            "[ICE] Could NOT find an entry in the valid list for media %p "\
            "corresponding to given candidate pair", media);

    return NULL;
}



int32_t ice_utils_update_media_checklist_state(
                    ice_media_stream_t *media, ice_cand_pair_t *valid_pair)
{
    int32_t status;

    /**
     * RFC 5245 Sec 8.1.2 Updating States
     */

    /** at this stage, the media state must be Running for further processing */
    if (media->state != ICE_MEDIA_CC_RUNNING) return STUN_OK;

    /** 
     * if there are no nominated pairs in the valid 
     * list for a media stream and the state of the 
     * checklist is Running, ICE processing continues.
     */
    if (ice_utils_get_nominated_pairs_count(media) == 0) return STUN_OK;

    /**
     * If there is at least one nominated pair in the valid list for a
     * media stream and the state of the check list is Running:
     */

    status = ice_media_utils_stop_checks_for_comp_id(
                                        media, valid_pair->local->comp_id);

    /**
     * Once there is at least one nominated pair in the valid list for
     * every component of at least one media stream and the state of the
     * check list is Running:
     *
     * - The agent MUST change the state of processing for its check
     *   list for that media stream to Completed.
     */
    if(ice_media_utils_have_nominated_list(media) == true)
    {
        media->state = ICE_MEDIA_CC_COMPLETED;
    }

    return STUN_OK;
}



uint32_t ice_utils_get_nominated_pairs_count(ice_media_stream_t *media)
{
    uint32_t i, count;

    for (i = 0, count = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
        if (media->ah_cand_pairs[i].nominated == true) count++;

    return count;
}



int32_t ice_media_utils_stop_checks_for_comp_id(
                            ice_media_stream_t *media, uint32_t comp_id)
{
    uint32_t i;
    ice_cand_pair_t *cp;

    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        cp = &media->ah_cand_pairs[i];
        if (cp->local == NULL) continue;

        if (cp->local->comp_id != comp_id) continue;

        /** now component id's match */

        /** 
         * The agent MUST remove all Waiting and Frozen pairs in 
         * the check list and triggered check queue for the same 
         * component as the nominated pairs for that media stream.
         */
        if ((cp->state == ICE_CP_FROZEN) || (cp->state == ICE_CP_WAITING))
        {
            /** 
             * first remove this candidate pair from 
             * triggered check queue, if present 
             */
            ice_utils_remove_from_triggered_check_queue(media, cp);

            cp->local = NULL;
            cp->remote = NULL;
            cp->state = ICE_CP_STATE_MAX;
        }
        else if (cp->state == ICE_CP_INPROGRESS)
        {
            /** TODO =
             * If an In-Progress pair in the check list is for the same
             * component as a nominated pair, the agent SHOULD cease
             * retransmissions for its check if its pair priority is lower
             * than the lowest-priority nominated pair for that component.
             */
        }
    }

    return STUN_OK;
}



void ice_utils_remove_from_triggered_check_queue(
                        ice_media_stream_t *media, ice_cand_pair_t *cp)
{
    ice_trigger_check_node_t *iter, *lag;

    if (media->trig_check_list == NULL) return;

    iter = media->trig_check_list;
    lag = NULL;
    while (iter != NULL)
    {
        if (iter->cp == cp)
        {
            if (lag)
            {
                lag->next = iter->next;
            }
            else
            {
                media->trig_check_list = iter->next;
            }

            ICE_LOG(LOG_SEV_DEBUG, 
                    "[ICE MEDIA] Removed specified node from triggered check "\
                    "list for media %p", media);
            stun_free(iter);
            return;
        }

        lag = iter;
        iter = iter->next;
    }

    ICE_LOG(LOG_SEV_ERROR, 
            "[ICE MEDIA] Could not find specified node in triggered check "\
            "list for media %p. Hence not removed node from triggered check "\
            "list", media);
    return;
}



bool_t ice_media_utils_have_valid_list(ice_media_stream_t *media)
{
    uint32_t i;
    bool_t rtp_valid, rtcp_valid;
    ice_cand_pair_t *cp;

    rtp_valid = rtcp_valid = false;
    
    ICE_LOG(LOG_SEV_DEBUG, 
            "[ICE MEDIA] Checking for valid candidate pairs in the media %p",
            media);

    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        cp = &media->ah_cand_pairs[i];
        if (cp->local == NULL) continue;

        if (cp->valid_pair == false) continue;

        if (cp->local->comp_id == RTP_COMPONENT_ID)
            rtp_valid = true;
        else if (cp->local->comp_id == RTCP_COMPONENT_ID)
            rtcp_valid = true;
    }

    if ((rtp_valid == true) && (media->num_peer_comp == 1))
    {
        ICE_LOG(LOG_SEV_INFO,
                "[ICE MEDIA] Number of components for this media %p is %d. "\
                "And valid candidate pairs are available for each of the "\
                "component", media, media->num_peer_comp);
        return true;
    }

    if ((rtp_valid == true) && (rtcp_valid == true))
    {
        ICE_LOG(LOG_SEV_INFO,
                "[ICE MEDIA] Number of components for this media %p is %d. "\
                "And valid candidate pairs are available for each of the "\
                "components", media, media->num_peer_comp);
        return true;
    }
    else 
    {
        ICE_LOG(LOG_SEV_INFO,
                "[ICE MEDIA] Number of components for this media %p is %d. "\
                "And valid candidate pairs are NOT YET available for each of "\
                "the components", media, media->num_peer_comp);
        return false;
    }
}



ice_cand_pair_t *ice_utils_select_nominated_cand_pair(
                                ice_media_stream_t *media, uint32_t comp_id)
{
    uint32_t i;
    ice_cand_pair_t *cp = NULL, *np = NULL;

    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        cp = &media->ah_cand_pairs[i];
        if (cp->local == NULL) continue;
        if (cp->valid_pair == false) continue;

        if (cp->local->comp_id != comp_id) continue;

        if (np == NULL)
            np = cp;
        else if (cp->priority > np->priority)
            np = cp;
    }

    return np;
}



int32_t ice_media_utils_init_turn_gather_candidates(
                            ice_media_stream_t *media, handle h_turn_inst, 
                            handle transport_param, handle *h_new_session)
{
    int32_t status;
    handle h_turn_session;

    status = turn_create_session(h_turn_inst, &h_turn_session);
    if (status != STUN_OK) return status;

    ICE_LOG(LOG_SEV_DEBUG, 
            "[ICE MEDIA] TURN session created handle %p", h_turn_session);

    status = turn_session_set_app_param(h_turn_inst, 
                                        h_turn_session, (handle) media);
    if (status != STUN_OK) goto ERROR_EXIT;

    status = turn_session_set_transport_param(
                        h_turn_inst, h_turn_session, transport_param);
    if (status != STUN_OK) goto ERROR_EXIT;

    status = turn_session_set_relay_server_cfg(h_turn_inst, h_turn_session,
                        (turn_server_cfg_t *)&media->ice_session->turn_cfg);
    if (status != STUN_OK) goto ERROR_EXIT;

    status = turn_session_allocate(h_turn_inst, h_turn_session);
    if (status != STUN_OK) goto ERROR_EXIT;

    *h_new_session = h_turn_session;
    return status;

ERROR_EXIT:
    turn_destroy_session(h_turn_inst, h_turn_session);
    return status;
}



int32_t ice_media_utils_init_stun_gather_candidates(
                            ice_media_stream_t *media, handle h_bind_inst, 
                            handle transport_param, handle *h_new_session)
{
    int32_t status;
    handle h_bind_session;
    ice_stun_server_cfg_t *stun_cfg;

    status = stun_binding_create_session(h_bind_inst, 
                            STUN_BIND_CLIENT_SESSION, &h_bind_session);
    if (status != STUN_OK) return status;

    ICE_LOG(LOG_SEV_DEBUG, 
            "[ICE MEDIA] STUN binding session created handle %p", 
            h_bind_session);

    status = stun_binding_session_set_app_param(h_bind_inst, 
                                        h_bind_session, (handle) media);
    if (status != STUN_OK) goto ERROR_EXIT;

    status = stun_binding_session_set_transport_param(
                        h_bind_inst, h_bind_session, transport_param);
    if (status != STUN_OK) goto ERROR_EXIT;

    stun_cfg = &media->ice_session->stun_cfg;
    status = stun_binding_session_set_stun_server(h_bind_inst, 
            h_bind_session, stun_cfg->server.host_type,
            stun_cfg->server.ip_addr, stun_cfg->server.port);
    if (status != STUN_OK) goto ERROR_EXIT;

    status = stun_binding_session_enable_session_refresh(
            h_bind_inst, h_bind_session, ICE_BINDING_KEEP_ALIVE_TIMER_VALUE);
    if (status != STUN_OK) goto ERROR_EXIT;

    status = stun_binding_session_send_message(
                    h_bind_inst, h_bind_session, STUN_REQUEST);
    if (status != STUN_OK) goto ERROR_EXIT;

    *h_new_session = h_bind_session;
    return status;

ERROR_EXIT:
    stun_binding_destroy_session(h_bind_inst, h_bind_session);
    return status;
}



ice_candidate_t *ice_media_utils_get_host_cand_for_transport_param(
                        ice_media_stream_t *media, ice_rx_stun_pkt_t *rx_msg)
{
    uint32_t i;
    ice_candidate_t *base = NULL;

    for (i = 0; i < ICE_CANDIDATES_MAX_SIZE; i++)
    {
        if ((media->as_local_cands[i].transport_param 
                                    == rx_msg->transport_param) &&
            (media->as_local_cands[i].type == ICE_CAND_TYPE_HOST))
        {
            base = &media->as_local_cands[i];
            break;
        }
    }

    return base;
}



void ice_media_utils_cleanup_triggered_check_queue(ice_media_stream_t *media)
{
    ice_trigger_check_node_t *iter, *head;

    head = iter = media->trig_check_list;
    while(iter)
    {
        iter = head->next;
        stun_free(head);
        head = iter;
    }

    media->trig_check_list = NULL;
    return;
}



int32_t ice_media_utils_send_keepalive_msg(
                        ice_media_stream_t *media, ice_cand_pair_t *np)
{
    int32_t status;
    handle h_bind_inst, h_bind_session;

    h_bind_inst = media->ice_session->instance->h_bind_inst;

    status = stun_binding_create_session(h_bind_inst, 
                            STUN_BIND_CLIENT_SESSION, &h_bind_session);
    if (status != STUN_OK) return status;

    status = stun_binding_session_set_app_param(h_bind_inst, 
                                        h_bind_session, (handle) media);
    if (status != STUN_OK) goto ERROR_EXIT;

    status = stun_binding_session_set_transport_param(
                h_bind_inst, h_bind_session, np->local->transport_param);
    if (status != STUN_OK) goto ERROR_EXIT;

    status = stun_binding_session_set_stun_server(h_bind_inst, 
            h_bind_session, np->remote->transport.type,
            np->remote->transport.ip_addr, np->remote->transport.port);
    if (status != STUN_OK) goto ERROR_EXIT;

    status = stun_binding_session_send_message(
                    h_bind_inst, h_bind_session, STUN_INDICATION);
    if (status != STUN_OK) goto ERROR_EXIT;

ERROR_EXIT:
    stun_binding_destroy_session(h_bind_inst, h_bind_session);
    return status;

}



int32_t ice_media_utils_update_nominated_pair_for_comp(
                        ice_media_stream_t *media, ice_cand_pair_t *cp)
{
    int32_t i, status = STUN_OK;

    for (i = 0; i < ICE_MAX_COMPONENTS; i++)
    {
        if (media->media_comps[i].comp_id == cp->local->comp_id)
            break;
    }

    if (i == ICE_MAX_COMPONENTS) return STUN_INT_ERROR;

    if (media->media_comps[i].np == NULL)
    {
        media->media_comps[i].np = cp;
    }
    else
    {
        ice_cand_pair_t *cur_np = media->media_comps[i].np;

        if (cp->priority > cur_np->priority)
            media->media_comps[i].np = cp;
    }

    return status;
}



int32_t ice_media_utils_clear_turn_session(ice_media_stream_t *media, 
                                    handle h_turn_inst, handle h_turn_session)
{
    int32_t i, status = STUN_OK;

    turn_clear_session(h_turn_inst, h_turn_session);

    /** remove the reference for this turn session in the media context */
    for (i = 0; i < ICE_MAX_COMPONENTS; i++)
        if (media->h_turn_sessions[i] == h_turn_session)
            media->h_turn_sessions[i] = NULL;

    return status;
}



int32_t ice_media_utils_clear_media_stream(ice_media_stream_t *media)
{
    int32_t i, count = 0;
    ice_session_t *session = media->ice_session;

    if (!media) return STUN_INVALID_PARAMS;

    if (media->o_removed == false) return STUN_OK;

    /** 
     * check if media has been removed. If so, then free the media context 
     * only after all the related turn sessions have been destroyed.
     */
    for (i = 0; i < ICE_MAX_MEDIA_STREAMS; i++)
        if (media->h_turn_sessions[i] != NULL)
            count++;

    if (count) return STUN_OK;

    /** remove the reference for this media stream in the session context */
    for (i = 0; i < ICE_MAX_MEDIA_STREAMS; i++)
        if (session->aps_media_streams[i] == media)
            session->aps_media_streams[i] = NULL;

    stun_free(media);

    /** check if session has been destroyed */
    if (session->o_destroyed == true)
    {
        if (session->instance)
        {
            /** 
             * free the session context only after all 
             * the media streams have been destroyed.
             */
            count = 0;

            for (i = 0; i < ICE_MAX_MEDIA_STREAMS; i++)
                if (session->aps_media_streams[i] != NULL)
                    count++;

            if (count == 0)
            {
                /** clear references of this session in the instance */
                for (i = 0; i < ICE_MAX_CONCURRENT_SESSIONS; i++)
                    if (session->instance->aps_sessions[i] == (handle)session)
                        session->instance->aps_sessions[i] = NULL;

                count = 0;
                for (i = 0; i < ICE_MAX_CONCURRENT_SESSIONS; i++)
                    if (session->instance->aps_sessions[i] != NULL)
                        count++;

                if (count == 0) stun_free(session);
            }
        }
    }

    return STUN_OK;
}



bool_t ice_utils_host_compare (u_char *host1, 
                    u_char *host2, stun_inet_addr_type_t addr_type)
{
    int32_t retval, size, family;
    u_char addr1[ICE_SIZEOF_IPV6_ADDR] = {0};
	u_char addr2[ICE_SIZEOF_IPV6_ADDR] = {0};

    if (addr_type == STUN_INET_ADDR_IPV4)
    {
        family = AF_INET;
        size = ICE_SIZEOF_IPV4_ADDR;
    }
    else if (addr_type == STUN_INET_ADDR_IPV6)
    {
        family = AF_INET6;
        size = ICE_SIZEOF_IPV6_ADDR;
    }
    else
        return false;

    retval = inet_pton(family, (const char *)host1, &addr1);
    if (retval != 1)
    {
        ICE_LOG(LOG_SEV_INFO, 
            "[ICE UTILS] inet_pton failed, probably invalid address [%s]", 
            host1);
        return false;
    }

    retval = inet_pton(family, (const char *)host2, &addr2);
    if (retval != 1)
    {
        ICE_LOG(LOG_SEV_INFO, 
            "[ICE UTILS] inet_pton failed, probably invalid address [%s]",
            host2);
        return false;
    }
    
    retval = stun_memcmp(addr1, addr2, size);
    if (retval == 0)
    {
        ICE_LOG(LOG_SEV_DEBUG, 
            "[ICE UTILS] Given IP addresses matched");
        return true;
    }

    ICE_LOG(LOG_SEV_DEBUG, 
            "[ICE UTILS] Given IP addresses differ");

    return false;
}



ice_cand_pair_t *ice_media_utils_search_cand_pair(ice_media_stream_t *media, 
                                ice_candidate_t *local, ice_candidate_t *remote)
{
    ice_cand_pair_t *cp = NULL;
    ice_cand_pair_t *temp_cp = NULL;
    uint32_t i;

    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        temp_cp = &media->ah_cand_pairs[i];

        if ((temp_cp->local == local) && (temp_cp->remote == remote))
        {
            cp = temp_cp;
            break;
        }
    }

    return cp;
}



ice_cand_pair_t *ice_media_utils_get_associated_valid_pair_for_cand_pair(
                                ice_media_stream_t *media, ice_cand_pair_t *cp)
{
    ice_cand_pair_t *temp_cp = NULL;
    uint32_t i;

    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        temp_cp = &media->ah_cand_pairs[i];

        if ((temp_cp->valid_pair == true) && 
            (temp_cp->local->comp_id == cp->local->comp_id) && 
            (temp_cp->remote == cp->remote))
        {
            break;
        }
    }

    return temp_cp;
}



ice_cand_pair_t *ice_media_utils_get_associated_nominated_pair_for_cand_pair(
                                ice_media_stream_t *media, ice_cand_pair_t *cp)
{
    ice_cand_pair_t *temp_cp = NULL;
    uint32_t i;

    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        temp_cp = &media->ah_cand_pairs[i];

        if ((temp_cp->nominated == true) && 
            (temp_cp->local->comp_id == cp->local->comp_id) && 
            (temp_cp->remote == cp->remote))
        {
            break;
        }
    }

    return temp_cp;
}



int32_t ice_utils_handle_role_conflict_response(
                ice_cand_pair_t *cp, conn_check_result_t *result)
{
    int32_t status = STUN_OK;
    bool_t role_changed = false;

    /** sec 7.1.2.1 Failure cases - Applicable only for STUN client */
    /**
     * If the request had contained the ICE-CONTROLLED 
     * attribute, the agent MUST switch to the controlling 
     * role if it has not already done so. If the request 
     * had contained the ICE-CONTROLLING attribute, the 
     * agent MUST switch to the controlled role if it has 
     * not already done so.
     */
    if ((result->controlling_role == true) &&
        (cp->media->ice_session->role == ICE_AGENT_ROLE_CONTROLLING))
    {
        cp->media->ice_session->role = ICE_AGENT_ROLE_CONTROLLED;
        role_changed = true;

        ICE_LOG(LOG_SEV_WARNING, 
                "ICE AGENT ROLE for the session changed to CONTROLLED");
    }
    else if ((result->controlling_role == false) &&
            (cp->media->ice_session->role == ICE_AGENT_ROLE_CONTROLLED))
    {
        cp->media->ice_session->role = ICE_AGENT_ROLE_CONTROLLING;
        role_changed = true;

        ICE_LOG(LOG_SEV_WARNING, 
                "ICE AGENT ROLE for the session changed to CONTROLLING");
    }

    /**
     * once it has switched, the agent must enqueue the 
     * candidate pair whose check generated the 487 into 
     * the triggered check queue.
     *
     * Note, however, that the tie-breaker value must not 
     * be reselected.
     */
    if (role_changed == true)
    {
        status = ice_utils_add_to_triggered_check_queue(cp->media, cp);

        /** The state of that pair is set to waiting */
        status = ice_cand_pair_fsm_inject_msg(cp, ICE_CP_EVENT_UNFREEZE, NULL);
    }

    return status;
}



void ice_utils_check_for_role_change(
        ice_media_stream_t *media, conn_check_result_t *check_result)
{
    if ((check_result->controlling_role == true) &&
            (media->ice_session->role == ICE_AGENT_ROLE_CONTROLLED))
    {
        media->ice_session->role = ICE_AGENT_ROLE_CONTROLLING;
        ICE_LOG(LOG_SEV_WARNING, 
                "[ICE] Agent role for this session switched to CONTROLLING");
    }

    if ((check_result->controlling_role == false) &&
            (media->ice_session->role == ICE_AGENT_ROLE_CONTROLLING))
    {
        media->ice_session->role = ICE_AGENT_ROLE_CONTROLLED;
        ICE_LOG(LOG_SEV_WARNING, 
                "[ICE] Agent role for this session switched to CONTROLLED");
    }

    return;
}



bool_t ice_media_utils_did_all_checks_fail(ice_media_stream_t *media)
{
    uint32_t i;
    ice_cand_pair_t *cp = NULL;

    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        cp = &media->ah_cand_pairs[i];
        if(cp->local == NULL) continue;

        if (cp->state != ICE_CP_FAILED)
        {
            /** atleast one candidate pair is still alive */
            return false;
        }
    }

    return true;
}



int32_t ice_utils_process_conn_check_response(ice_media_stream_t *media, 
            ice_rx_stun_pkt_t *stun_pkt, handle h_cc_inst, handle h_cc_dialog)
{
    int32_t status = STUN_OK;
    ice_cand_pair_t *cp = NULL;

    /** received connectivity check binding response */
    status = conn_check_session_inject_received_msg(h_cc_inst, 
                            h_cc_dialog, (conn_check_rx_pkt_t *) stun_pkt);
    if (status == STUN_TERMINATED)
    {
        conn_check_result_t check_result;

        /** 
         * connectivity check terminated. Retrieve the overall
         * result of the connectivity check and feed it to the 
         * corresponding cand pair fsm. Then destroy the 
         * connectivity check session if no longer required.
         */
        status = ice_utils_find_cand_pair_for_conn_check_session(
                                                media, h_cc_dialog, &cp);
        if (status == STUN_OK)
        {
            status = conn_check_session_get_check_result(
                                h_cc_inst, h_cc_dialog, &check_result);

            if (check_result.check_succeeded == true)
            {
                ice_candidate_t *local_cand;
                ice_cand_pair_t *pair = NULL;

                ICE_LOG (LOG_SEV_INFO, 
                        "[ICE MEDIA] Connectivity check succeeded");

                status = ice_cand_pair_fsm_inject_msg(
                        cp, ICE_EP_EVENT_CHECK_SUCCESS, &check_result);

                /**
                 * RFC 5245 7.1.3.2.1 Discovering Peer Reflexive Candidates
                 * search the mapped address in the received response 
                 * against the list local canidates.
                 */
                status = ice_utils_search_local_candidates(
                        media, &(check_result.mapped_addr), &local_cand);
                if (status == STUN_OK)
                {
                    ICE_LOG (LOG_SEV_INFO, 
                            "[ICE MEDIA] The mapped address discovered "\
                            "from connectivity check is already present "\
                            "in the media local candidate list");
                }
                else if (status == STUN_NOT_FOUND)
                {
                    ICE_LOG (LOG_SEV_INFO, 
                            "[ICE MEDIA] The mapped address discovered "\
                            "from connectivity check is NOT present "\
                            "in the media local candidate list. Adding "\
                            "local peer reflexive candidate ...");
                     
                    status = ice_utils_add_local_peer_reflexive_candidate(
                              cp, &(check_result.mapped_addr), &local_cand);
                }

                /**
                 * RFC 5245 7.1.3.2.2 Constructing a Valid pair
                 * Check if there exists a candidate pair in this media
                 * check list with mapped address as local address and 
                 * remote destination address of the connectivity check.
                 */
                pair = ice_media_utils_search_cand_pair(
                                            media, local_cand, cp->remote);

                if (pair == NULL)
                {
                    ICE_LOG(LOG_SEV_INFO,
                        "[ICE] Did not find the candidate pair on "\
                        "current check list, hence adding a new "\
                        "candidate pair to check list.");

                    /** not found, the pair is not on any check list */
                    status = ice_media_utils_add_new_candidate_pair(
                                    media, local_cand, cp->remote, &pair);

                    /** the check has already succeeded for this pair */
                    pair->state = ICE_CP_SUCCEEDED;
                }
                else
                {
                    /** found, the pair is already available on the check list */
                    ICE_LOG(LOG_SEV_INFO,
                        "[ICE] Found the candidate pair on current check list");
                }

                pair->valid_pair = true;
                pair->nominated = check_result.nominated;

                ICE_LOG(LOG_SEV_INFO,
                        "[ICE] Added candidate pair to VALID list."\
                        " From %s %d ==> To %s %d", 
                        pair->local->transport.ip_addr, 
                        pair->local->transport.port, 
                        pair->remote->transport.ip_addr, 
                        pair->remote->transport.port);

                /**
                 * It is possible that when this agent is in controlled 
                 * role, the peer controlling agent might have already
                 * nominated a candidate pair, say using aggressive
                 * nomination, when this check is still in progress. So
                 * check for the condition now.
                 */
                if (media->ice_session->role == ICE_AGENT_ROLE_CONTROLLED)
                {
                    ice_cand_pair_t *temp = 
                        ice_media_utils_get_associated_nominated_pair_for_cand_pair(media, pair);
                    if (temp)
                    {
                        temp->nominated = false;
                        pair->nominated = true;
                    }
                }

                /**
                 * RFC 5245 Sec 7.1.3.2.3 Updating Pair States
                 * - The agent changes the states for all other Frozen
                 *   pairs for the same media stream and same foundation
                 *   to Waiting.
                 */
                status = ice_media_utils_update_cand_pair_states(media, cp);
                if (status != STUN_OK)
                {
                    ICE_LOG(LOG_SEV_WARNING,
                            "[ICE] Updating the candidate pair states of "\
                            "the media failed - %d", status);

                    /** just fallthrough ... */
                }

                /** 
                 * RFC 5245 10. KeepAlives
                 * An agent MUST begin the keepalive processing once 
                 * ICE has selected candidates for usage with media, 
                 * or media begins to flow, whichever happens first.
                 */
                if (pair->nominated == true)
                {
                    ice_media_utils_update_nominated_pair_for_comp(media, pair);

                    status = ice_utils_start_keep_alive_timer_for_comp(
                                                media, pair->local->comp_id);
                    if (status != STUN_OK)
                    {
                        ICE_LOG(LOG_SEV_ERROR, 
                                "[ICE] Starting of Keep Alive timer failed");
                    }

                    /**
                     * If there is atleast one nominated pair in the valid list
                     * for a media stream and the state of the checklist is 
                     * running
                     * - The agent must remove all waiting and frozen pairs in
                     *   the check list and triggered queue for the same 
                     *   component as the nominated pairs.
                     */
                    status = ice_media_utils_cease_checks_for_nominated_comp(
                                                                   media, pair);
                    if (status != STUN_OK)
                    {
                        ICE_LOG(LOG_SEV_ERROR, 
                                "[ICE] Unable to cease other checks for the "\
                                "same component as the nominated pair");

                        /** its ok, we can live with it */
                    }
                }

                /**
                 * Once there is at least one nominated pair in the 
                 * valid list for every component of at least one 
                 * media stream and the state of the check list is
                 * Running:
                 *
                 * - The agent MUST change the state of processing 
                 *   for its check list for that media stream to 
                 *   Completed.
                 */
                if(ice_media_utils_have_nominated_list(media) == true)
                {
                    media->state = ICE_MEDIA_CC_COMPLETED;

                    /** unfreeze checks for other media streams */
                    status = ice_utils_unfreeze_checks_for_other_media_streams(media, pair);
                }

                /**
                 * Once there is a valid pair for every component of the media
                 * stream and the agent is in CONTROLLING mode and regular
                 * nomination is being used, then proceed with nomination.
                 */
                if ((media->state == ICE_MEDIA_CC_RUNNING) && 
                        (media->ice_session->role == ICE_AGENT_ROLE_CONTROLLING) && 
                        (media->ice_session->instance->nomination_mode == ICE_NOMINATION_TYPE_REGULAR))
                    if(ice_media_utils_have_valid_list_for_all_components(media) == true)
                    {
                        ice_media_utils_initiate_nomination(media);

                        /** cancel nomination timer */
                        ice_media_utils_stop_nomination_timer(media);
                    }
            }
            else
            {
                status = ice_cand_pair_fsm_inject_msg(
                        cp, ICE_CP_EVENT_CHECK_FAILED, &check_result);

                /** RFC 5245 7.1.3.1 Failure Cases */
                if (check_result.error_code == STUN_ERROR_ROLE_CONFLICT)
                {
                    status = ice_utils_handle_role_conflict_response(
                                                        cp, &check_result);

                    if (status != STUN_OK)
                        ICE_LOG(LOG_SEV_ERROR,
                            "[ICE] Handling of 487 Role Conflict response "\
                            "failed");
                }

                if (ice_media_utils_did_all_checks_fail(media) == true)
                {
                    /** all checks have failed */
                    media->state = ICE_MEDIA_CC_FAILED;
                }
            }

            status = conn_check_destroy_session(h_cc_inst, h_cc_dialog);
            if (status != STUN_OK)
            {
                ICE_LOG(LOG_SEV_ERROR, 
                        "Destroying of connectivity check session "\
                        "failed %d", status);
            }

            if (cp->h_cc_session == h_cc_dialog)
            {
                cp->h_cc_session = NULL;
                if (cp->h_cc_cancel)
                {
                    conn_check_destroy_session(h_cc_inst, cp->h_cc_cancel);
                    cp->h_cc_cancel = NULL;
                }
            }
            else if (cp->h_cc_cancel == h_cc_dialog)
            {
                cp->h_cc_cancel = NULL;
                if (cp->h_cc_session)
                {
                    conn_check_destroy_session(h_cc_inst, cp->h_cc_session);
                    cp->h_cc_session = NULL;
                }
            }

            ice_media_utils_dump_cand_pair_stats(media);
        }
        else
        {
            ICE_LOG(LOG_SEV_ERROR,
                    "[ICE MEDIA] Unable to find candidate pair for "\
                    "the connectivity check session");
            status = STUN_INT_ERROR;
        }
    }
    else if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, 
            "[ICE MEDIA] conn_check_session_inject_received_msg() "\
            "returned error %d\n", status);
        return status;
    }

    return status;
}



int32_t ice_media_utils_unfreeze_checks_with_same_foundation(
        ice_media_stream_t *media, ice_cand_pair_t *cur_cp, bool_t *match)
{
    ice_cand_pair_t *cp;
    int32_t i, status = STUN_OK;

    /** RFC 5245 Sec 7.1.3.2.3 Updating Pair States */
    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        cp = &media->ah_cand_pairs[i];
        if (cp->local == NULL) continue;

        if (cp == cur_cp) continue;
        if (cp->state != ICE_CP_FROZEN) continue;

        if ((stun_strncmp((char *)cp->local->foundation, 
                          (char *)cur_cp->local->foundation, 
                          ICE_FOUNDATION_MAX_LEN) == 0) &&
            (stun_strncmp((char *)cp->remote->foundation, 
                          (char *)cur_cp->remote->foundation,
                          ICE_FOUNDATION_MAX_LEN) == 0))
        {
            /** foundation of these both candidate pairs match */
            status = ice_cand_pair_fsm_inject_msg(
                                    cp, ICE_CP_EVENT_UNFREEZE, NULL);
            if (status != STUN_OK)
            {
                ICE_LOG(LOG_SEV_ERROR,
                        "[ICE] Unfreezing of the candidate pair failed");
                continue;
            }

            *match = true;
        }
    }

    return STUN_OK;
}



int32_t ice_media_utils_group_and_unfreeze_pairs(ice_media_stream_t *media)
{
    int32_t status, i, j, group_count;
    ice_foundation_pairs_t fnd_groups[ICE_MAX_CANDIDATE_PAIRS];
    ice_foundation_pairs_t *ptr = NULL;
    ice_cand_pair_t *cp;
    bool_t fnd_match;

    group_count = 0;
    stun_memset(fnd_groups, 0, 
            (sizeof(ice_foundation_pairs_t) * ICE_MAX_CANDIDATE_PAIRS));

    /** group together all of the pairs with the same foundation */
    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        fnd_match = false;

        cp = &media->ah_cand_pairs[i];
        if (cp->local == NULL) continue;

        for (j = 0; j < group_count; j++)
        {
            ptr = &fnd_groups[j];

            if ((stun_strncmp((char *)cp->local->foundation, 
                              (char *)ptr->local_fnd, 
                              ICE_FOUNDATION_MAX_LEN) == 0) &&
                (stun_strncmp((char *)cp->remote->foundation, 
                              (char *)ptr->remote_fnd,
                              ICE_FOUNDATION_MAX_LEN) == 0))
            {
                int k;

                fnd_match = true;

                for (k = 0; k < ICE_MAX_CANDIDATE_PAIRS; k++)
                {
                    if (ptr->pairs[k] == 0)
                    {
                        ptr->pairs[k] = cp;
                        break;
                    }

                    if (k == ICE_MAX_CANDIDATE_PAIRS)
                    {
                        ICE_LOG(LOG_SEV_CRITICAL, "[ICE] Unable to add "\
                                        "candidate pair to foundation list");
                        return STUN_NO_RESOURCE;
                    }
                }
            }
        }

        /** foundations did not match, add a new group */
        if (fnd_match == false)
        {
            ptr = &fnd_groups[group_count];
            group_count++;

            stun_memcpy(ptr->local_fnd, 
                    cp->local->foundation, ICE_FOUNDATION_MAX_LEN);
            stun_memcpy(ptr->remote_fnd, 
                    cp->remote->foundation, ICE_FOUNDATION_MAX_LEN);

            ptr->pairs[0] = cp;
        }
    }

    /**
     * for each group, set the state of the pair with the lowest 
     * component ID to Waiting. If there is more than one such pair, 
     * the one with the highest priority is used.
     */
    for (i = 0; i < group_count; i++)
    {
        int32_t lowest_compid = 0;
        ice_cand_pair_t *chosen_cp = NULL;
        
        ptr = &fnd_groups[i];

        for (j = 0; j < ICE_MAX_CANDIDATE_PAIRS; j++)
        {
            cp = ptr->pairs[j];
            if (cp == NULL) continue;

            if (cp->local->comp_id > lowest_compid)
            {
                lowest_compid = cp->local->comp_id;
                chosen_cp = cp;
            }
            else if (cp->local->comp_id == lowest_compid)
            {
                if (cp->priority > chosen_cp->priority)
                    chosen_cp = cp;
            }
        }

        if (chosen_cp)
        {
            status = ice_cand_pair_fsm_inject_msg(
                                    chosen_cp, ICE_CP_EVENT_UNFREEZE, NULL);
            if (status != STUN_OK)
            {
                ICE_LOG(LOG_SEV_ERROR,
                        "[ICE] Unfreezing of the candidate pair failed");
                return STUN_INT_ERROR;
            }

            media->state = ICE_MEDIA_CC_RUNNING;
        }
    }

    return STUN_OK;
}



int32_t ice_utils_unfreeze_checks_for_other_media_streams(
                            ice_media_stream_t *cur_media, ice_cand_pair_t *cp)
{
    int32_t i, j, status = STUN_OK;
    ice_media_stream_t *media = NULL;
    ice_session_t *session = cur_media->ice_session;
    bool_t match = false;

    for (i = 0; i < ICE_MAX_MEDIA_STREAMS; i++)
    {
        media = session->aps_media_streams[i];
        if (!media) continue;
        if (media == cur_media) continue;

        /** either checklist is active or frozen */
        if ((media->state == ICE_MEDIA_CC_RUNNING) || 
                (media->state == ICE_MEDIA_NOMINATING) || 
                (media->state == ICE_MEDIA_CC_COMPLETED) ||
                (media->state == ICE_MEDIA_FROZEN))
        {
            for (j = 0; j < ICE_MAX_COMPONENTS; j++)
            {
                ice_media_utils_unfreeze_checks_with_same_foundation(
                                media, cur_media->media_comps[j].np, &match);
                if(match == true)
                {
                    media->state = ICE_MEDIA_CC_RUNNING;
                    ICE_LOG(LOG_SEV_INFO, 
                            "[ICE] Media unfreezed, moved into RUNNING");
                }
            }
        }
        
        if (media->state == ICE_MEDIA_FROZEN)
        {
            ice_media_utils_group_and_unfreeze_pairs(media);
        }
    }

    return status;
}



int32_t ice_media_utils_cease_checks_for_nominated_comp(
                            ice_media_stream_t *media, ice_cand_pair_t *nom_cp)
{
    int32_t i;
    ice_cand_pair_t *cp = NULL;
    ice_trigger_check_node_t *node, *temp;

    node = media->trig_check_list;
    temp = NULL;

    /** 
     * remove all waiting and frozen pairs in the triggered check queue for 
     * the same component as the nominated pairs for that media stream.
     */
    while(node != NULL)
    {
        if (node->cp->local->comp_id == nom_cp->local->comp_id)
        {
            if ((node->cp->state == ICE_CP_FROZEN) || 
                (node->cp->state == ICE_CP_WAITING))
            {
                if (node == media->trig_check_list)
                {
                    temp = node;
                    node = node->next;
                    stun_free(temp);
                    temp = NULL;
                    media->trig_check_list = node;
                    continue;
                }
                else
                {
                    temp->next = node->next;
                    stun_free(node);
                    node = temp->next;
                    continue;
                }
            }
        }

        temp = node;
        node = node->next;
    }


    /** 
     * remove all waiting and frozen pairs in the checklist for 
     * the same component as the nominated pairs for that media stream.
     */
    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        cp = &media->ah_cand_pairs[i];
        if (cp->local == NULL) continue;

        if (cp->local->comp_id != nom_cp->local->comp_id) continue;

        if ((cp->state == ICE_CP_FROZEN) || (cp->state == ICE_CP_WAITING))
        {
            /** remove the candidate pair */
            cp->local = NULL;
            cp->remote = NULL;
            cp->state = ICE_CP_STATE_MAX;
            cp->media = NULL;
        }
        else if (cp->state == ICE_CP_INPROGRESS)
        {
            /** 
             * cease re-transmission if this pair priority is lower than 
             * the lowest priority nominated pair for that component.
             */
            if (cp->priority < nom_cp->priority)
            {
                conn_check_cancel_session(
                    media->ice_session->instance->h_cc_inst, cp->h_cc_session);
            }
        }
    }

    return STUN_OK;
}



int32_t ice_utils_process_binding_keepalive_response(
                ice_media_stream_t *media, ice_rx_stun_pkt_t *stun_pkt)
{
    int32_t status;
    handle h_bind_inst, h_bind_session;

    h_bind_inst = media->ice_session->instance->h_bind_inst;

    /** find session */
    status = stun_binding_instance_find_session_for_received_msg(
                            h_bind_inst, stun_pkt->h_msg, &h_bind_session);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_WARNING, 
                "[ICE MEDIA] Unable to find a stun binding session for the "\
                "received response message. Dropping the message");
        stun_msg_destroy(stun_pkt->h_msg);
        return status;
    }

    ICE_LOG(LOG_SEV_INFO, "[ICE] This is a stun binding refresh reponse");

    /** inject received message */
    status = stun_binding_session_inject_received_msg(
                            h_bind_inst, h_bind_session, stun_pkt->h_msg);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_WARNING, 
                "[ICE] STUN binding session returned failure: [%d]", status);
    }

    /**
     * Even if the stun binding response is a failure, it is not treated as
     * failure for the overall ice session here since the purpose of stun 
     * binding transaction is to refresh the port bindings at the NATs which
     * is served by the request and response messages.
     */

    return STUN_OK;
}



bool_t ice_media_utils_have_valid_list_for_all_components(ice_media_stream_t *media)
{
    uint32_t i;
    bool_t rtp_valid, rtcp_valid;
    ice_cand_pair_t *cp;

    rtp_valid = rtcp_valid = false;
    
    ICE_LOG(LOG_SEV_DEBUG, 
            "[ICE MEDIA] Checking for valid candidate pairs in "\
            "the media %p.", media);

    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        cp = &media->ah_cand_pairs[i];
        if (cp->local == NULL) continue;
        if (cp->valid_pair == false) continue;

        if (cp->local->comp_id == RTP_COMPONENT_ID)
            rtp_valid = true;
        else if (cp->local->comp_id == RTCP_COMPONENT_ID)
            rtcp_valid = true;
    }

    if (rtp_valid == true)
    {
        ICE_LOG(LOG_SEV_DEBUG, "RTP is validated");
    }

    if (rtcp_valid == true)
    {
        ICE_LOG(LOG_SEV_DEBUG, "RTCP is validated");
    }

    if ((rtp_valid == true) && (media->num_peer_comp == 1))
    {
        ICE_LOG(LOG_SEV_INFO,
                "[ICE MEDIA] Number of components for this media %p is %d. "\
                "And valid candidate pair is available for each of the "\
                "component", media, media->num_peer_comp);
        return true;
    }

    if ((rtp_valid == true) && (rtcp_valid == true))
    {
        ICE_LOG(LOG_SEV_INFO,
                "[ICE MEDIA] Number of components for this media %p is %d. "\
                "And valid candidate pairs are available for each of "\
                "the components", media, media->num_peer_comp);
        return true;
    }
    else 
    {
        ICE_LOG(LOG_SEV_INFO,
                "[ICE MEDIA] Number of components for this media %p is %d. "\
                "And valid candidate pairs are NOT YET available for "\
                "each of the components", media, media->num_peer_comp);
        return false;
    }
}



int32_t ice_media_utils_initiate_nomination(ice_media_stream_t *media)
{
    int32_t count, status;
    ice_cand_pair_t *np;

    for (count = 0; count < media->num_comp; count++)
    {
        np = ice_utils_select_nominated_cand_pair(media, (count + 1));
        
        /** 
         * no need for return value check since we have already verified 
         * availability of the validated pair for each component 
         */

        /*
         * When the controlling agent selects the valid pair, it repeats the
         * check that produced this valid pair (by enqueuing the pair that
         * generated the check into the triggered check queue), this time with
         * the USE-CANDIDATE attribute.
         */

        ICE_LOG(LOG_SEV_INFO,
                "[ICE MEDIA] Candidate pair %p current state %d", 
                np, np->state);

        np->check_nom_status = true;

        status = ice_utils_add_to_triggered_check_queue(media, np);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR,
                    "[ICE MEDIA] Adding of nominating candidate pair %p for "\
                    "component %d to triggered list for media %p failed", 
                    np, (count + 1), media);
            
            media->state = ICE_MEDIA_CC_FAILED;

            return STUN_INT_ERROR;
        }

        ICE_LOG(LOG_SEV_INFO,
                "[ICE MEDIA] Added nominating candidate pair %p for component "\
                "%d to triggered list for media %p", np, (count + 1), media);
    }

    /** 
     * make sure the checklist timer is running. If stopped, 
     * then restart it so that the nominated triggered checks
     * that we have added above, are processed 
     */
    if (media->checklist_timer->timer_id == 0)
    {
        status = ice_media_utils_start_check_list_timer(media);
    }

    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_INFO,
                "[ICE MEDIA] Unable to start the checklist timer after adding"\
                " the nominated pairs to triggered queue for media %p", media);
    }
    else
    {
        media->state = ICE_MEDIA_NOMINATING;
    }

    return STUN_OK;
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
