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
#include "turn_api.h"
#include "ice_api.h"
#include "ice_int.h"
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

    if ((media_params->media_state == ICE_CC_RUNNING) ||
        (media_params->media_state == ICE_GATHERED))
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
            cand->comp_id = peer_cand->component_id;

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

    return STUN_OK;
}



uint64_t ice_utils_compute_candidate_priority(ice_candidate_t *cand)
{
    uint32_t type_pref;
    uint32_t local_pref;
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

    if(cand->transport.type == STUN_INET_ADDR_IPV4)
        local_pref = LOCAL_PREF_IPV4;
    else if (cand->transport.type == STUN_INET_ADDR_IPV6)
        local_pref = LOCAL_PREF_IPV6;
    else
        return 0;

    prio = (pow(2, 24) * type_pref) + 
           (pow(2, 8) * local_pref) + 
           (256 - cand->comp_id);

    return prio;
}


uint64_t ice_utils_compute_peer_reflexive_candidate_priority(
                                                    ice_candidate_t *cand)
{
    uint32_t type_pref;
    uint32_t local_pref;
    uint64_t prio;

    if (cand == NULL) return STUN_INVALID_PARAMS;

    type_pref = CAND_TYPE_PREF_PRFLX_CANDIDATE;

    if(cand->transport.type == STUN_INET_ADDR_IPV4)
        local_pref = LOCAL_PREF_IPV4;
    else if (cand->transport.type == STUN_INET_ADDR_IPV6)
        local_pref = LOCAL_PREF_IPV6;
    else
        return 0;

    prio = (pow(2, 24) * type_pref) + 
           (pow(2, 8) * local_pref) + 
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

                pair->state = ICE_CP_FROZEN;
                pair->media = media;

                /** compute the pair priority as per sec 5.7.2 */
                ice_media_utils_compute_candidate_pair_priority(media, pair);
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

#ifdef DEBUG
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

#ifdef DEBUG        
        ICE_LOG (LOG_SEV_DEBUG, "Hi Pair state: %s component id: %d local "\
               "candidate : %p remote candidate: %p\n", 
               cand_pair_states[pair_hi->state], pair_hi->local->comp_id, 
               pair_hi->local, pair_hi->remote);
#endif

        for (j = i+1; j < ICE_MAX_CANDIDATE_PAIRS; j++)
        {
            pair_lo = &media->ah_cand_pairs[j];
        
            if (!pair_lo->local) continue;

#ifdef DEBUG
            ICE_LOG (LOG_SEV_DEBUG, "Low Pair state: %s component id: %d "\
                    "local candidate : %p remote candidate: %p\n", 
                    cand_pair_states[pair_lo->state], pair_lo->local->comp_id,
                    pair_lo->local, pair_lo->remote);
#endif

            if ((pair_hi->local == pair_lo->local) &&
                (pair_hi->remote == pair_lo->remote))
            {
                stun_memset(pair_lo, 0, sizeof(ice_cand_pair_t));
                ICE_LOG(LOG_SEV_DEBUG, "pruned one cand pair");
            }

        }

#ifdef DEBUG
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

#ifdef DEBUG
                    ICE_LOG(LOG_SEV_CRITICAL, "value i:%d and j:%d", i, j);
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
    ice_cand_pair_t *pair;

    ICE_LOG (LOG_SEV_DEBUG, 
            "===============================================================");

    ICE_LOG (LOG_SEV_DEBUG, 
            "\ncount: [comp_id] source --> dest state [ priority foundation ]\n");


    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        pair = &media->ah_cand_pairs[i];

        if (!pair->local) continue;

        count++;
        ICE_LOG (LOG_SEV_DEBUG, 
                "%d: [%d] %s:%d --> %s:%d %s [ %lld %s:%s ]\n", count, 
                pair->local->comp_id, pair->local->transport.ip_addr, 
                pair->local->transport.port, pair->remote->transport.ip_addr, 
                pair->remote->transport.port, cand_pair_states[pair->state], 
                pair->priority, pair->local->foundation, 
                pair->remote->foundation);
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


int32_t ice_media_utils_get_next_connectivity_check_pair(
        ice_media_stream_t *media, ice_cand_pair_t **pair)
{
    int32_t status, i, z = 99999;
    ice_cand_pair_t *cand_pair, *hi_prio_pair;

    hi_prio_pair = NULL;
    status = STUN_OK;

    /** section 5.8 - scheduling checks */

    /** TODO - first check for triggered check queue */

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

    if (hi_prio_pair == NULL)
    {
        /** we are here because there is no pair in the WAITING state */
        
        ICE_LOG(LOG_SEV_DEBUG, 
                "No more candidate pair in the WAITING state. Now need to "\
                "choose the candidate with the highest priority pair in the "\
                "FROZEN state = TODO");

        /** 
         * find the highest priority pair in that check list that is 
         * in the FROZEN state 
         */

        /** TODO */
        return STUN_INT_ERROR;
    }

    /**
     * TODO - 
     * If there is no pair in the FROZEN state, then terminate the timer
     * for the particular check list
     */
    ICE_LOG(LOG_SEV_DEBUG, 
            "No more candidate pair in the FROZEN state. So terminate"\
            "the check list timer and go to sleep + TODO");

    return status;
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

    ICE_LOG (LOG_SEV_ERROR, 
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

    /** TODO following is TEMPORARY = set local credentials */
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

    /** TODO following is TEMPORARY = set peer credentials */
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

    /** TODO following is TEMPORARY = set session behavioral parameters  */
    cc_params.controlling_role = true; // FIXME
    cc_params.nominated = false;
    cc_params.prflx_cand_priority = 
        ice_utils_compute_peer_reflexive_candidate_priority(pair->local);
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


int32_t ice_utils_nominate_candidate_pair(
        ice_session_t *session, ice_cand_pair_t *pair)
{
    int32_t status = STUN_OK;
    conn_check_session_params_t cc_params;

    handle h_cc_inst;

    h_cc_inst = session->instance->h_cc_inst;

    status = conn_check_create_session(h_cc_inst, 
                                    CC_CLIENT_SESSION, &pair->h_cc_session);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, 
            "conn_check_create_session() returned error %d\n", status);
    }

    //status = conn_check_session_set_transport_param(
    //                        h_cc_inst, pair->h_cc_session, 
    //                        session->as_local_candidates[0].transport_param);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, 
            "conn_check_session_set_transport_param() returned error %d\n", 
            status);
    }

    status = conn_check_session_set_peer_transport_params(h_cc_inst, 
                            pair->h_cc_session, 
                            pair->remote->transport.type,
                            pair->remote->transport.ip_addr,
                            pair->remote->transport.port);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, 
            "conn_check_session_set_peer_transport_params() returned "\
            "error %d\n", status);
    }

    /** set the ice session handle as application handle */
    status = conn_check_session_set_app_param(h_cc_inst, pair->h_cc_session, session);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, 
            "conn_check_session_set_app_param() returned error %d\n", status);
    }

    /** TODO = session params - need to fill */
    status = conn_check_session_set_session_params(h_cc_inst, 
                                                pair->h_cc_session, &cc_params);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, 
            "conn_check_session_set_nominated() returned error %d\n", status);
    }

    status = conn_check_session_initiate_check(h_cc_inst, pair->h_cc_session);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, 
            "conn_check_session_initiate_check() returned error %d\n", status);
    }

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
        if ((session->aps_media_streams[i]) && 
            (session->aps_media_streams[i]->state == ICE_MEDIA_CC_RUNNING))
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

        j += 1;
    }

    valid_pairs->num_valid = j;

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
    int32_t comp_loop, i, comp_id;
    int32_t rtp_vp_cnt, rtcp_vp_cnt, vp_index = 0;
    ice_cand_pair_t *vp = &media->ah_valid_pairs[vp_index];

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
        
        if ((rtp_vp_cnt == 1) && (rtcp_vp_cnt == 1))
        {
            media->state = ICE_MEDIA_CC_COMPLETED;
        }
        else
        {
            /**
             * if there is more than one pair per component, then select a pair
             * based on local policy. Further, the media state should not move
             * to COMPLETED. This is because both the ice lite parties might 
             * have chosen different valid pair. To reconcile this, the 
             * controlling agent must send an updated offer with the 
             * remote-candidates attributes set to the chosen pair.
             *
             * The local policy here is left to the application. The stack will
             * provide all the valid pairs per component to the application.
             * But the state media stream will remains in RUNNING state.
             */
        }
    }
    
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
                                ice_candidate_t *base_cand)
{
    stun_memcpy(cand->transport.ip_addr, 
                        alloc_addr->ip_addr, ICE_IP_ADDR_MAX_LEN);
    cand->transport.port = alloc_addr->port;
    cand->transport.protocol = ICE_TRANSPORT_UDP; /** TODO */

    cand->type = cand_type;
    cand->comp_id = comp_id;

    cand->base = base_cand;
    cand->default_cand = false;
    cand->transport_param = base_cand->transport_param;

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
               " component id", comp_id);
        return STUN_INT_ERROR;
    }

    status = ice_utils_get_free_local_candidate(media, &cand);
    if (status == STUN_NO_RESOURCE) return status;

    /** copy server reflexive candidate information */
    ice_utils_copy_gathered_candidate_info(cand, 
                            &alloc_info.mapped_addr, ICE_CAND_TYPE_SRFLX, 
                            comp_id, base_cand);

    status = ice_utils_get_free_local_candidate(media, &cand);
    if (status == STUN_NO_RESOURCE) return status;

    /** copy relay candidate information */
    ice_utils_copy_gathered_candidate_info(cand, 
                            &alloc_info.relay_addr, ICE_CAND_TYPE_RELAYED, 
                            comp_id, base_cand);

    return STUN_OK;
}



int32_t ice_media_utils_start_check_list_timer(ice_media_stream_t *media)
{
    int32_t status;
    uint32_t cc_timer_value;
    ice_timer_params_t *timer = media->cc_timer;

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
                                            cc_timer_value, media->cc_timer);
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


int32_t ice_utils_find_cand_pair_for_conn_check_session(
        ice_media_stream_t *media, handle h_conn_check, ice_cand_pair_t **cp)
{
    int32_t i;
    ice_cand_pair_t *pair;

    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {
        pair = &media->ah_cand_pairs[i];
        if (!pair->local) continue;

        if (pair->h_cc_session == h_conn_check)
        {
            *cp = pair;
            return STUN_OK;
        }
    }

    return STUN_NOT_FOUND;
}



void ice_utils_handle_agent_role_conflict(
                ice_media_stream_t *media, ice_agent_role_type_t new_role)
{
    ice_session_t *ice_session = media->ice_session;

    ICE_LOG(LOG_SEV_INFO, "Changing the AGENT ROLE for the session");

    ice_session->role = new_role;

    return;
}



int32_t ice_utils_search_local_candidates(ice_media_stream_t *media, 
                    conn_check_result_t *check, ice_candidate_t **found_cand)
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

        /** 
         * Note 1: not checking the transport protocol, UDP is assumed.
         * Note 2: strncmp is not proper way to compare ip addresses, 
         *         especially ipv6 
         */
        if((local_cand->transport.type == check->prflx_addr.host_type) &&
           (local_cand->transport.port == check->prflx_addr.port) &&
           (stun_strncmp((char *)local_cand->transport.ip_addr, 
                 (char *)check->prflx_addr.ip_addr, ICE_IP_ADDR_MAX_LEN) == 0))
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



int32_t ice_utils_add_peer_reflexive_candidate(ice_cand_pair_t *cp, 
                    conn_check_result_t *check, ice_candidate_t **new_prflx)
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
    prflx_cand->transport.type = check->prflx_addr.host_type;
    memcpy(prflx_cand->transport.ip_addr, 
                        check->prflx_addr.ip_addr, ICE_IP_ADDR_MAX_LEN);
    prflx_cand->transport.port = check->prflx_addr.port;

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

    /** calculation of priority is bit different from spec - revisit? */
    prflx_cand->priority = 
        ice_utils_compute_peer_reflexive_candidate_priority(prflx_cand);

    prflx_cand->default_cand = false;
    prflx_cand->base = cp->local;

    /** TODO = foundation */
    stun_strncpy((char *)prflx_cand->foundation, "4", 1);

    *new_prflx = prflx_cand;

    return STUN_OK;
}


int32_t ice_utils_add_valid_pair(ice_media_stream_t *media, 
                            ice_candidate_t *prflx_cand, ice_rx_stun_pkt_t *pkt)
{
    int32_t i;
    ice_cand_pair_t *valid_pair;

    /** find a free slot for the new valid pair */
    for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
    {                    
        valid_pair = &media->ah_valid_pairs[i];
        if (valid_pair->local == NULL) break;
    }

    if (i == ICE_MAX_CANDIDATE_PAIRS)
    {
        ICE_LOG(LOG_SEV_ERROR,
                "No more slots left for adding the new valid pair for media");
        return STUN_NO_RESOURCE;
    }

    valid_pair->local = prflx_cand;
    valid_pair->remote = 
        ice_utils_get_peer_cand_for_pkt_src(media, &(pkt->src));

    if (valid_pair->remote == NULL)
    {
        ICE_LOG (LOG_SEV_WARNING, 
            "Ignored binding request from unknown source");
        valid_pair->local = NULL;
        return STUN_OK;
    }

    ICE_LOG (LOG_SEV_WARNING, "Added new valid pair for the media");

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

        status = turn_session_send_message(h_turn_inst, 
                                           media->h_turn_sessions[i], 
                                           STUN_METHOD_CREATE_PERMISSION, 
                                           STUN_REQUEST);
        if (status != STUN_OK) break;
    }

    return status;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
