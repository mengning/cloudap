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

/*
 * Parse the PDU to struct wpa_init_params *params
 * input	: char * pdu , Memory allocate outside
 * output	: struct wpa_init_params *params , Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int wpa_init_params_parser(char * pdu, int pdu_size,struct wpa_init_params *params);
/*
 * Format the struct wpa_init_params *params to the PDU
 * output	: char * pdu , Memory allocate outside
 * input	: struct wpa_init_params *params , Memory allocate outside
 * return	: SUCCESS(0)/FAILURE(-1)
 *
 */
int wpa_init_params_format(char * pdu, int pdu_size,struct wpa_init_params *params);

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
int i802_bss_format(char * pdu, int pdu_size,struct i802_bss *bss);

#endif /* _WI_FLOW_H_ */


