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


#include "stun_base.h"
#include "msg_layer_api.h"
#include "conn_check_api.h"
#include "turn_api.h"
#include "ice_api.h"
#include "ice_int.h"
#include "ice_utils.h"
#include "ice_media_fsm.h"
#include "ice_session_fsm.h"


#define ICE_VALIDATE_MEDIA_HANDLE(h_media) { \
    for (i = 0; i < ICE_MAX_MEDIA_STREAMS; i++) \
        if (session->aps_media_streams[i] == h_media) { break; } \
\
    if (i == ICE_MAX_MEDIA_STREAMS) { \
        ICE_LOG(LOG_SEV_ERROR, "Invalid media handle"); \
        return STUN_INVALID_PARAMS; \
    } \
} \


static ice_session_fsm_handler 
    ice_session_fsm[ICE_SES_STATE_MAX][ICE_SES_EVENT_MAX] =
{
    /** ICE_SES_IDLE */
    {
        gather_candidates,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_add_media_stream,
        ice_ignore_msg,
    },
    /** ICE_SES_GATHERING */
    {
        ice_ignore_msg,
        handle_gather_result,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        process_relay_server_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
    },
    /** ICE_SES_GATHERED */
    {
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_form_checklist,
        initiate_checks,
        ice_ignore_msg,
        handle_peer_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_remote_params,
        ice_ignore_msg,
        ice_ignore_msg,
    },
    /** ICE_SES_CC_RUNNING */
    {
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_nominate,
        handle_peer_msg,
        ice_handle_checklist_timer_expiry,
        ice_restart,
        ice_remote_params,
        ice_ignore_msg,
        ice_remove_media_stream,
    },
    /** ICE_SES_CC_COMPLETED */
    {
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        handle_peer_msg,
        ice_ignore_msg,
        ice_restart,
        ice_remote_params,
        ice_ignore_msg,
        ice_remove_media_stream,
    },
    /** ICE_SES_CC_FAILED */
    {
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_remove_media_stream,
    },
    /** ICE_SES_NOMINATING */
    {
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_completed,
        handle_peer_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_remove_media_stream,
    },
    /** ICE_SES_ACTIVE */
    {
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_ignore_msg,
        ice_remove_media_stream,
    }
};



int32_t gather_candidates(ice_session_t *session, handle h_msg, handle *h_param)
{
    int32_t i, status;
    ice_media_stream_t *media;

    for (i = 0; i < session->num_media_streams; i++)
    {
        /** media streams are already created */
        media = session->aps_media_streams[i];

        /* initiate candidate gathering */
        status = ice_media_stream_fsm_inject_msg(media, ICE_MEDIA_GATHER, NULL);
        if(status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                    "Initiation of candidate gathering for media %d failed.", i);
            return STUN_INT_ERROR;
        }
    }

    status = ice_utils_determine_session_state(session);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Unable to determine ICE session state.");
    }

    //session->state = ICE_SES_GATHERING;

    return status;
}



int32_t handle_gather_result(ice_session_t *session, 
                                            handle h_msg, handle *h_param)
{
    int32_t status;
    ice_int_params_t *param = (ice_int_params_t *)h_msg;
    ice_media_stream_t *media;

    status = turn_session_get_app_param(
                        param->h_inst, param->h_session, (handle *)&media);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "unable to get application param from TURN handle");
        return status;
    }

    status = ice_media_stream_fsm_inject_msg(media, 
                                        ICE_MEDIA_GATHER_RESP, h_msg);
    if(status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "processing of gathered candidates by media fsm failed");
        goto EXIT_PT;
    }

    status = ice_utils_determine_session_state(session);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Unable to determine ICE session state.");
    }

EXIT_PT:
    return status;
}



int32_t process_relay_server_msg (ice_session_t *session, 
                                            handle h_msg, handle *h_param)
{
    int32_t status, index;
    stun_msg_type_t msg_class;
    stun_method_type_t method;
    ice_rx_stun_pkt_t *stun_pkt = (ice_rx_stun_pkt_t *) h_msg;
    ice_media_stream_t *media;

    stun_msg_get_class(stun_pkt->h_msg, &msg_class);
    stun_msg_get_method(stun_pkt->h_msg, &method);

    /** 
     * at this stage, we only entertain responses from relay server
     * for turn alloc requests initiated by this session.
     */
    if (method != STUN_METHOD_ALLOCATE) return STUN_INVALID_PARAMS;
    if ((msg_class != STUN_SUCCESS_RESP) && (msg_class != STUN_ERROR_RESP))
        return STUN_INVALID_PARAMS;

    status = ice_utils_find_media_for_transport_handle(
                                session, stun_pkt->transport_param, &index);
    if(status == STUN_NOT_FOUND)
    {
        ICE_LOG (LOG_SEV_ERROR, 
            "Could not find media handle for the received message with "\
            "transport param %p\n", stun_pkt->transport_param);

        return STUN_INVALID_PARAMS;
    }

    ICE_LOG (LOG_SEV_INFO, "Found media stream for received message");

    media = session->aps_media_streams[index];

    status = ice_media_stream_fsm_inject_msg(media, ICE_MEDIA_RELAY_MSG, h_msg);
    if(status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Injecting of received stun message failed.");
        return STUN_INT_ERROR;
    }

    status = ice_utils_determine_session_state(session);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Unable to determine ICE session state.");
    }

    return status;
}

int32_t ice_form_checklist(ice_session_t *session, 
                                            handle h_msg, handle *h_param)
{
    int32_t i, status = STUN_INVALID_PARAMS;
    ice_media_stream_t *media;

    for (i = 0; i < ICE_MAX_MEDIA_STREAMS; i++)
    {
        media = session->aps_media_streams[i];
        if (!media) continue;

        /* check list must be formed for each media stream */
        status = ice_media_stream_fsm_inject_msg(
                            media, ICE_MEDIA_FORM_CHECKLIST, NULL);
        if(status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                "Forming of check list for media stream %d failed.", i);
            return STUN_INT_ERROR;
        }
    }

    /** 
     * once the checklists for all the media are prepared, initially all 
     * the media checklists and their candidate pairs are in frozen state.
     */

    /** we remain in the ICE_GATHERED state */

    return status;
}



int32_t initiate_checks(ice_session_t *session, handle h_msg, handle *h_param)
{
    int32_t status;
    ice_media_stream_t *media;

    /**
     * when the check lists are formed, initially all are in frozen
     * state. Now when connectivity checks are initiated, the first
     * media stream is made active (this is the fist m-line in the SDP
     * offer and answer) and connectivity checks are started.
     */
    media = session->aps_media_streams[0];

    /** lets go */
    status = ice_media_stream_fsm_inject_msg(
                        media, ICE_MEDIA_UNFREEZE, NULL);
    if(status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
            "Unfreezing of the checklist for first media failed.");
        return STUN_INT_ERROR;
    }

    session->state = ICE_SES_CC_RUNNING;
     
    return status;
}


int32_t handle_peer_msg (ice_session_t *session, handle pkt, handle *h_param)
{
    int32_t status, index, count;
    stun_msg_type_t msg_class;
    stun_method_type_t method;
    ice_rx_stun_pkt_t *stun_pkt = (ice_rx_stun_pkt_t *) pkt;
    ice_media_stream_t *media;

    stun_msg_get_class(stun_pkt->h_msg, &msg_class);
    stun_msg_get_method(stun_pkt->h_msg, &method);

    /** 
     * at this stage, we only entertain responses to connectivity checks 
     * initiated by this session and new incoming stun binding requests
     */
    if (method != STUN_METHOD_BINDING) return STUN_INVALID_PARAMS;
    if (msg_class == STUN_INDICATION) return STUN_INVALID_PARAMS;

    status = ice_utils_find_media_for_transport_handle(
                                session, stun_pkt->transport_param, &index);
    if(status == STUN_NOT_FOUND)
    {
        ICE_LOG (LOG_SEV_ERROR, 
            "Could not find media handle for the received message with "\
            "transport param %p\n", stun_pkt->transport_param);

        return STUN_INVALID_PARAMS;
    }

    ICE_LOG (LOG_SEV_INFO, "Found media stream for received message");

    media = session->aps_media_streams[index];

    status = ice_media_stream_fsm_inject_msg(media, ICE_MEDIA_CC_MSG, pkt);
    if(status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Injecting of received stun message failed.");
        return STUN_INT_ERROR;
    }

    /** 
     * for an ice-lite agent, session becomes completed as soon 
     * as connectivity checks are done and valid pairs are
     * present for each component of each media, that is, each
     * media moves into COMPLETED state
     */
    count = 0;
    for (index = 0; index < ICE_MAX_MEDIA_STREAMS; index++)
    {
        media = session->aps_media_streams[index];
        if (!media) continue;

        if(media->state == ICE_MEDIA_CC_COMPLETED) count++;
    }

    if (count == session->num_media_streams)
    {
        ICE_LOG(LOG_SEV_DEBUG, 
            "All media streams have moved to ICE_MEDIA_CC_COMPLETED state. "\
            "Hence ICE session state entering ICE_SES_CC_COMPLETED state");
        session->state = ICE_SES_CC_COMPLETED;
    }

    return STUN_OK;
}


int32_t ice_nominate(ice_session_t *session, handle h_msg, handle *h_param)
{
    int32_t status = STUN_OK;

    if (session->role == ICE_AGENT_ROLE_CONTROLLED)
    {
        ICE_LOG (LOG_SEV_DEBUG, "Waiting for the peer to nominate a pair\n");
        session->state = ICE_CC_COMPLETED;
    }
    else
    {
        /** well as of now, we always nominate the first pair */
        //status = ice_utils_nominate_candidate_pair(session, &session->ah_candidate_pairs[0]);
        //if (status != STUN_OK) return status;

        session->state = ICE_SES_NOMINATING;
    }

    return status;
}


int32_t ice_completed(ice_session_t *session, handle h_msg, handle *h_param)
{
    session->state = ICE_SES_ACTIVE;

    return STUN_OK;
}

int32_t ice_handle_checklist_timer_expiry(ice_session_t *session, 
                                                    handle arg, handle *h_param)
{
    int32_t status;
    ice_timer_params_t *timer = (ice_timer_params_t *) arg;
    ice_media_stream_t *media;

    media = (ice_media_stream_t *)timer->h_media;

    /** TODO - need a check for media handle? */
    status = ice_media_stream_fsm_inject_msg(
                        media, ICE_MEDIA_CHECKLIST_TIMER, arg);
    if(status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
            "Unfreezing of the checklist for first media failed.");
        return STUN_INT_ERROR;
    }

    return status;
}


int32_t ice_restart (ice_session_t *session, handle arg, handle *h_param)
{
    int32_t i, status = STUN_INVALID_PARAMS;
    ice_media_stream_t *media;

    for (i = 0; i < ICE_MAX_MEDIA_STREAMS; i++)
    {
        if (arg != session->aps_media_streams[i]) continue;

        media = session->aps_media_streams[i];

        /* restart the specified media stream */
        status = ice_media_stream_fsm_inject_msg(
                            media, ICE_MEDIA_RESTART, NULL);
        if(status == STUN_OK)
        {
            /**
             * RFC 5245 sec 9.3.2 Procedures for Lite Implementations
             * The state of ICE processing for each media stream 
             * MUST change to Running, and the state of ICE 
             * processing MUST change to Running.
             */
            session->state = ICE_SES_CC_RUNNING;
        }
        else
        {
            ICE_LOG(LOG_SEV_ERROR, 
                "restarting of media stream %d failed.", i);
        }
    }

    return status;
}


int32_t ice_remote_params (ice_session_t *session, handle arg, handle *h_param)
{
    int32_t i, j, status;
    ice_media_stream_t *media;
    ice_media_params_t *media_params;
    ice_session_params_t *session_params = (ice_session_params_t *) arg;

    for (i = 0; i < session_params->num_media; i++)
    {
        media_params = &session_params->media[i];
        if (!media_params) continue;

        for (j = 0; j < ICE_MAX_MEDIA_STREAMS; j++)
        {
            media = session->aps_media_streams[j];
            if (media_params->h_media == media) break;
        }

        if (j == ICE_MAX_MEDIA_STREAMS)
        {
            ICE_LOG(LOG_SEV_ERROR, "Media handle not found in the session");
            return STUN_INVALID_PARAMS;
        }

        status = ice_media_stream_fsm_inject_msg(media, 
                                    ICE_MEDIA_REMOTE_PARAMS, media_params);
        if(status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                    "Processing of remote media params failed");
            return STUN_INT_ERROR;
        }
    }

    if (session->peer_mode != session_params->ice_mode)
    {
        /** update the peer ice implementation mode */
        session->peer_mode = session_params->ice_mode;
    }

    /**
     * if this session's current implementation is ice-lite and remote/peer 
     * implementation for this session is ice-lite, then ice session moves
     * to COMPLETED state.
     */
    if ((session->local_mode == ICE_MODE_LITE) &&
        (session_params->ice_mode == ICE_MODE_LITE))
    {
        for (i = 0; i < ICE_MAX_MEDIA_STREAMS; i++)
        {
            media = session->aps_media_streams[i];
            if (!media) continue;

            /** propagate this info to all the media */
            status = ice_media_stream_fsm_inject_msg(media, 
                                                ICE_MEDIA_BOTH_LITE, NULL);
        }
    }

    status = ice_utils_determine_session_state(session);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Unable to determine ICE session state.");
    }

    return status;
}


int32_t ice_add_media_stream (ice_session_t *session, 
                                            handle h_msg, handle *h_param)
{
    int32_t i, status;
    ice_media_stream_t *media_stream;
    ice_api_media_stream_t *add_media = (ice_api_media_stream_t *) h_msg;

    /** find a free slot for the new media stream */
    for (i = 0; i < ICE_MAX_MEDIA_STREAMS; i++)
        if (session->aps_media_streams[i] == NULL) break;

    if (i == ICE_MAX_MEDIA_STREAMS) return STUN_NO_RESOURCE;

    /** allocate memory for media */
    media_stream = (ice_media_stream_t *)
                    stun_calloc (1, sizeof(ice_media_stream_t));
    if (media_stream == NULL) return STUN_MEM_ERROR;

    media_stream->ice_session = session;

    /** copy the media stream parameters */
    status = ice_utils_copy_media_host_candidates(add_media, media_stream);

    if (status != STUN_OK) goto EXIT_PT;

    /**
     * if this is an ice-lite session, then the media needs to be 
     * unfrozen so that it moves to RUNNING state
     */
    if (session->local_mode == ICE_MODE_LITE)
    {
        status = ice_media_stream_fsm_inject_msg(media_stream, 
                                            ICE_MEDIA_UNFREEZE, NULL);
        if(status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                "Unfreezing of media stream failed for this ice-lite session."\
               " Hence not moving into RUNNING state");
            status = STUN_INT_ERROR;
            goto EXIT_PT;
        }
    }

    session->aps_media_streams[i] = media_stream;
    session->num_media_streams++;

    *h_param = media_stream;

    /** determine the overall ice session state */
    status = ice_utils_determine_session_state(session);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Unable to determine ICE session state.");
        session->num_media_streams -= 1;
        session->aps_media_streams[i] = NULL;
        goto EXIT_PT;
    }

    return status;

EXIT_PT:
    stun_free(media_stream);
    return status;
}


int32_t ice_remove_media_stream (ice_session_t *session, 
                                            handle h_msg, handle *h_param)
{
    int32_t i;
    ice_media_stream_t *media = (ice_media_stream_t *) h_msg;

    /** verify media handle */
    ICE_VALIDATE_MEDIA_HANDLE(media);

    session->aps_media_streams[i] = NULL;

    /** initiate removing of the media */
    stun_free(media);

    session->num_media_streams--;

    /** no change in session state */
    
    return STUN_OK;
}


int32_t ice_ignore_msg (ice_session_t *session, handle h_msg, handle *h_param)
{
    return STUN_OK;
}


int32_t ice_session_fsm_inject_msg(ice_session_t *session, 
                ice_session_event_t event, handle h_msg, handle *h_param)
{
    int32_t status;
    ice_session_fsm_handler handler;
    ice_session_state_t cur_state;

    cur_state = session->state;
    handler = ice_session_fsm[cur_state][event];

    if (!handler)
        return STUN_INVALID_PARAMS;

    status = handler(session, h_msg, h_param);

    if (cur_state != session->state)
    {
        ice_session_utils_notify_state_change_event(session);
    }

    return status;
}

/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
