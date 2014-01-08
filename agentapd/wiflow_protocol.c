/********************************************************************/
/* Copyright (C) SSE-USTC, 2014                                     */
/*                                                                  */
/*  FILE NAME             :  wiflow_protocol.c                      */
/*  PRINCIPAL AUTHOR      :  Mengning                               */
/*  SUBSYSTEM NAME        :  driver_nl80211                         */
/*  MODULE NAME           :  WiFlow                                 */
/*  LANGUAGE              :  C                                      */
/*  TARGET ENVIRONMENT    :  ANY                                    */
/*  DATE OF FIRST RELEASE :  2014/01/08                             */
/*  DESCRIPTION           :  implement of WiFlow PDU parser         */
/********************************************************************/

/*
 * Revision log:
 *
 * Created by Mengning,2014/01/08 
 *
 */
#include<stdio.h> 			/* perror */
#include<stdlib.h>			/* exit	*/
#include<sys/types.h>		/* WNOHANG */
#include<sys/wait.h>		/* waitpid */
#include<string.h>			/* memset */

#include "common.h"
#include "driver.h"
#include "wiflow_protocol.h"

int wpa_init_params_parser(char * pdu, int pdu_size,struct wpa_init_params *params)
{
    return 0;
}

int wpa_init_params_format(char * pdu, int pdu_size,struct wpa_init_params *params)
{
    return 0;   
}

int i802_bss_parser(char * pdu, int pdu_size,struct i802_bss *bss)
{
    return 0;   
}

int i802_bss_format(char * pdu, int pdu_size,struct i802_bss *bss)
{
    return 0;   
}



