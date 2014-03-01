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
    WIFLOW_NL80211_SET_TX_QUEUE_PARAMS_REQUEST /*remote request call set_tx_queue_params func*/
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

int wiflow_pdu_format(char * pdu, int *pdu_size,int type);

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
 * Parse the PDU to struct ieee80211_mgmt *mgmt
 * input	: char * pdu , Memory allocate outside
 * output	: struct ieee80211_mgmt *mgmt , Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int wpa_ieee80211_mgmt_parser(char * pdu,int  p_size, struct ieee80211_mgmt *mgmt, size_t *data_len, int *encrypt);

/*
 * Parse the PDU to i802_set_wds_sta() argc
 * input	: char * pdu , Memory allocate outside
 * output	: i802_set_wds_sta() agrc , Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int wpa_i802_set_wds_sta_parser(char *pdu, int p_size, const u8 *addr, int aid, int val, const char *bridge_ifname);

/*
 * Parse the PDU to struct hostapd_sta_add_params * params
 * input	: char * pdu , Memory allocate outside
 * output	: struct hostapd_sta_add_params * params , Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int wpa_sta_add_parser(char * pdu, int p_size, struct hostapd_sta_add_params * params);

/*
 * Parse the PDU to if_add() argc
 * input	: char * pdu , Memory allocate outside
 * output	: if_add() agrc , Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int wpa_if_add_parser(char *pdu, int p_size, struct wpa_function_params *func_params);

/*
 * Parse the PDU to struct hostapd_freq_params * freq
 * input	: char * pdu , Memory allocate outside
 * output	: struct hostapd_freq_params * freq , Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int wpa_set_freq_parser(char * pdu, int * p_size, struct hostapd_freq_params * freq);

/*
 * Parse the PDU to sta_set_flags() argc
 * input	: char * pdu , Memory allocate outside
 * output	: sta_set_flags() agrc , Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int wpa_sta_set_flags_parser(char *pdu, int *p_size, u8 *addr, int* total_flags,
					    int* flags_or, int* flags_and);

/*
 * Parse the PDU to send_action() argc
 * input	: char * pdu , Memory allocate outside
 * output	: send_action() agrc , Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int wpa_send_action_parser(char * pdu,int * p_size, unsigned int freq, unsigned int wait_time, 
							const u8 * dst, const u8 * data,size_t data_len);

/*
 * Parse the PDU to struct wpa_set_tx_queue_params * tx_params
 * input	: char * pdu , Memory allocate outside
 * output	: struct wpa_set_tx_queue_params * tx_params , Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int wpa_set_tx_queue_params_parser(char * pdu, int p_size, struct wpa_set_tx_queue_params *tx_params);



#endif /* _WI_FLOW_H_ */


