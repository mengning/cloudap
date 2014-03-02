/********************************************************************/
/* Copyright (C) SSE-USTC, 2014                                     */
/*                                                                  */
/*  FILE NAME             :  wiflow_protocol.h                      */
/*  PRINCIPAL AUTHOR      :  Mengning                               */
/*  SUBSYSTEM NAME        :  driver_nl80211                         */
/*  MODULE NAME           :  WiFlow                                 */
/*  LANGUAGE              :  C                                      */
/*  TARGET ENVIRONMENT    :  ANY                                    */
/*  DATE OF FIRST RELEASE :  2014/01/08                             */
/*  DESCRIPTION           :  interface of WiFlow PDU parser         */
/********************************************************************/

/*
 * Revision log:
 *
 * Created by Mengning,2014/01/08 
 *
 */

#ifndef _WI_FLOW_H_
#define _WI_FLOW_H_

#define MAX_BUF_LEN             1024
#define MAX_ARG_NUM             10

/* this is ABI! */
enum wiflow_commands
{
    WIFLOW_INIT_PARAMS_REQUEST, /* agent request AP params */
    WIFLOW_INIT_PARAMS_RESPONSE, /* remote response AP params to agent */
    WIFLOW_NL80211_SET_OPERSTATE_REQUEST, /*remote request call set_operstate func*/
    WIFLOW_NL80211_HAPD_DEINIT_REQUEST, /*remote request call hapd_deinit func*/
    WIFLOW_NL80211_SEND_FRAME_REQUEST, /*remote request call send_fram func*/
    WIFLOW_NL80211_I802_SET_WDS_STA_REQUEST, /*remote request call i802_set_wds_sta func*/
    WIFLOW_NL80211_STA_ADD_REQUEST, /*remote request call sta_add func*/
    WIFLOW_NL80211_IF_ADD_REQUEST1, /*remote request call if_add func*/
    WIFLOW_NL80211_IF_ADD_REQUEST2,  /*remote request call if_add func*/
    WIFLOW_NL80211_SET_FREQ_REQUEST, /*remote request call set_freq func*/
    WIFLOW_NL80211_STA_SET_FLAGS_REQUEST, /*remote request call sta_set_flags func*/
    WIFLOW_NL80211_SEND_ACTION_REQUEST, /*remote request call send action func*/
    WIFLOW_NL80211_SET_TX_QUEUE_PARAMS_REQUEST, /*remote request call set_tx_queue_params func*/
    WIFLOW_NL80211_SCAN2_REQUEST, /*remote request call scan2 func*/
    WIFLOW_NL80211_STA_DEAUTH_REQUEST, /*remote request call sta_deauth func*/
    WIFLOW_NL80211_STA_DISASSOC_REQUEST, /*remote request call sta_disassoc func*/
    WIFLOW_NL80211_SET_KEY_REQUEST, /*remote request call set_key func*/
    WIFLOW_NL80211_SEND_MLME_REQUEST, /*remote request call send_mlme func*/
    WIFLOW_NL80211_GET_SCAN_RESULTS2_REQUEST /*remote request call get_scan_results2 func*/
}; 

struct wiflow_pdu_element
{
    int len;
    char data;
};

struct wiflow_pdu 
{
    int type;
    /* elements - struct wiflow_pdu_element */
};

int wiflow_pdu_format(char * pdu, int *pdu_size,enum wiflow_commands type);

/*
 * Parse the PDU to struct wpa_init_params *params
 * input	: pdu/pdu_size , Memory allocate outside
 * output	: struct wpa_init_params *params , Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int wpa_init_params_parser(char * pdu, int pdu_size,struct wpa_init_params *params);
/*
 * Format the struct wpa_init_params *params to the PDU
 * output	: pdu/pdu_size , Memory allocate outside
 * input	: struct wpa_init_params *params , Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int wpa_init_params_format(char * pdu, int *pdu_size,struct wpa_init_params *params);

/*
 * Parse the PDU to struct i802_bss *bss
 * input	: char * pdu , Memory allocate outside
 * output	: struct i802_bss *bss , Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int i802_bss_parser(char * pdu, int pdu_size,struct i802_bss *bss);
/*
 * Format the struct i802_bss *bss to the PDU
 * output	: char * pdu , Memory allocate outside
 * input	: struct i802_bss *bss , Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int i802_bss_format(char * pdu, int *pdu_size,struct i802_bss *bss);
/*
 * Format the struct ieee80211_mgmt *mgmt to the PDU
 * output	: char * pdu , Memory allocate outside
 * input	: struct ieee80211_mgmt *mgmt , Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int wpa_ieee80211_mgmt_format(char *pdu, int *p_size, const u8 *data, size_t data_len, int encrypt);

/*
 * Format the argc of i802_set_wds_sta function to the PDU
 * output	: char * pdu , Memory allocate outside
 * input	: the argc of i802_set_wds_sta function, Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int wpa_i802_set_wds_sta_format(char *pdu, int *p_size, const u8 *addr, int aid, int val, const char *bridge_ifname);

/*
 * Format the struct hostapd_sta_add_params to the PDU
 * output	: char * pdu , Memory allocate outside
 * input	: struct hostapd_sta_add_param , Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int wpa_sta_add_format(char *pdu, int *p_size,struct hostapd_sta_add_params *params);

/*
 * Format the argc of if_add function to the PDU
 * output	: char * pdu , Memory allocate outside
 * input	: the argc of if_add function, Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int wpa_if_add_format(char *pdu, int *p_size, enum wpa_driver_if_type type, const char *ifname, const u8 *addr, 
							void *bss_ctx, void **drv_priv, char *force_ifname, u8 *if_addr);

/*
 * Format the struct hostapd_freq_params *freq to the PDU
 * output	: char * pdu , Memory allocate outside
 * input	: struct hostapd_freq_params *freq , Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int wpa_set_freq_format(char *pdu, int *p_size, struct hostapd_freq_params *freq);

/*
 * Format the func argc to the PDU
 * output	: char * pdu , Memory allocate outside
 * input	: func argc, Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int wpa_sta_set_flags_format(char *pdu, int *p_size, const u8 *addr, int total_flags,
					    int flags_or, int flags_and);

/*
 * Format the func argc to the PDU
 * output	: char * pdu , Memory allocate outside
 * input	: func argc, Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int wpa_send_action_format(char *pdu, int *p_size, unsigned int freq, unsigned int wait_time,
					  const u8 *dst,
					  const u8 *data, size_t data_len);

/*
 * Format the set_tx_queue_params() func argc to the PDU
 * output	: char * pdu , Memory allocate outside
 * input	: func argc, Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int wpa_set_tx_queue_params_format(char * pdu, int * p_size, int queue, int aifs, int cw_min, int cw_max, int burst_time);

/*
* Format the struct wpa_driver_scan_params *params to the PDU
* output   : char * pdu , Memory allocate outside
* input    : struct wpa_driver_scan_params *params, Memory allocate outside
* return   : SUCCESS(0)/FAILURE(-1)
*
*/
int wpa_scan2_format(char * pdu, int * p_size, struct wpa_driver_scan_params *params, int data_len);

/*
 * Format the func argc to the PDU
 * output	: char * pdu , Memory allocate outside
 * input	: func argc, Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int wpa_sta_deauth_format(char * pdu, int * p_size, const u8 *addr, int reason);

/*
 * Format the func argc to the PDU
 * output	: char * pdu , Memory allocate outside
 * input	: func argc, Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int wpa_sta_disassoc_format (char * pdu, int * p_size, const u8 *addr, int reason);

/*
 * Format the func argc to the PDU
 * output	: char * pdu , Memory allocate outside
 * input	: func argc, Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int wpa_set_key_format(char * pdu, int * p_size, enum wpa_alg alg, const u8 *addr,
				      int key_idx, int set_tx, const u8 *seq, size_t seq_len,
				      const u8 *key, size_t key_len);

/*
 * Format the func argc to the PDU
 * output	: char * pdu , Memory allocate outside
 * input	: func argc, Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int wpa_send_mlme_format(char *pdu, int *p_size, const u8 *data, size_t data_len, int noack);

#endif /* _WI_FLOW_H_ */


