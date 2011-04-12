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

#ifndef ICE_MEDIA_FSM__H
#define ICE_MEDIA_FSM__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


int32_t ice_media_stream_gather_cands(
                                ice_media_stream_t *media, handle h_msg);


int32_t ice_media_process_relay_msg(ice_media_stream_t *media, handle h_msg);


int32_t ice_media_stream_check_gather_resp(
                                ice_media_stream_t *media, handle h_msg);


int32_t ice_media_stream_gather_failed(
                                ice_media_stream_t *media, handle h_msg);


int32_t ice_media_stream_form_checklist(
                                ice_media_stream_t *media, handle h_msg);


int32_t ice_media_unfreeze(ice_media_stream_t *media, handle h_msg);


int32_t ice_media_process_rx_msg(ice_media_stream_t *media, handle pkt);


int32_t ice_media_stream_checklist_timer_expiry(
                                ice_media_stream_t *media, handle arg);


int32_t ice_media_lite_mode(ice_media_stream_t *media, handle arg);


int32_t ice_media_stream_restart(ice_media_stream_t *media, handle arg);


int32_t ice_media_stream_remote_params(ice_media_stream_t *media, handle h_msg);


int32_t ice_media_stream_dual_ice_lite(ice_media_stream_t *media, handle h_msg);


int32_t ice_media_conn_check_timer_expiry(
                            ice_media_stream_t *media, handle h_msg);


int32_t ice_media_stream_evaluate_valid_pairs(
                                    ice_media_stream_t *media, handle arg);


int32_t ice_media_stream_keep_alive_timer_expiry(
                                ice_media_stream_t *media, handle arg);


int32_t ice_media_stream_ignore_msg(
                                ice_media_stream_t *media, handle h_msg);


int32_t ice_media_stream_fsm_inject_msg(ice_media_stream_t *media, 
                               ice_media_stream_event_t event, handle h_msg);



/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
