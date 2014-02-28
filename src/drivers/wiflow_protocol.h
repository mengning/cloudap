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
    WIFLOW_INIT_PARAMS_RESPONSE /* remote response AP params to agent */
    WIFLOW_INIT_CAPA_RESPONSE,             /*get capa from AP*/
    WIFLOW_INIT_CAPA_REQUEST
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

int wpa_init_capa_format(char * pdu, int *pdu_size,struct i802_bss *bss);

int wpa_init_capa_parser(char * pdu, int pdu_size,struct wpa_driver_capa *capa);

int local_default_capa(struct wpa_driver_capa *capa);

int wpa_set_country_format(char * pdu, int *pdu_size,const char *alpha2_arg);

int wpa_set_country_parser(char * pdu, int pdu_size,const char *alpha2_arg);


int wpa_get_hw_feature_format(char * pdu, int *pdu_size, u16 *num_modes, u16 *flags);


int local_default_hw_mode(struct hostapd_hw_modes *local_hw_mode);




#endif /* _WI_FLOW_H_ */


