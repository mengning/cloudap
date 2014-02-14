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
#include<assert.h>

#include "common.h"
#include "driver.h"
#include "wiflow_protocol.h"

#define MAX_SSID_LEN    32

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
/*
struct wpa_init_params {
	void *global_priv; //NOT used,use local global_priv
	const u8 *bssid;   //ETH_ALEN length
	const char *ifname;//sizeof(bss->ifname) or char ifname[IFNAMSIZ + 1]; ex.wlan0
	const u8 *ssid;    //ssid_len
	size_t ssid_len;    
	const char *test_socket;//NOT used
	int use_pae_group_addr;//NOT used
	char **bridge; //Not used here,its up to AP hardware
	size_t num_bridge;//Not used here,its up to AP hardware

	u8 *own_addr; // ETH_ALENlength,buffer for writing own MAC address 
};
*/
int wpa_init_params_parser(char * pdu, int pdu_size,struct wpa_init_params *params)
{
    struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int i = 0;
    int len;
    char * p;
    if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu) || params == NULL)
    {
        fprintf(stderr,"wpa_init_params_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,pdu_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
    if(wpdu->type != I802_INIT_PARAMS)
    {
        fprintf(stderr,"wpdu->type Error,%s:%d\n",__FILE__,__LINE__);
        goto err;   
    }
    counter += sizeof(struct wiflow_pdu);
    /* bssid */
    len = sizeof(element->len) + ETH_ALEN;
    if(pdu_size < counter + len)
    {
        fprintf(stderr,"bssid Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    p = malloc(ETH_ALEN);
    memcpy(p,&element->data,ETH_ALEN);
    params->bssid = (u8 *)p;
    counter += len;
    /* ifname */
    len = sizeof(element->len) + IFNAMSIZ + 1;
    if(pdu_size < counter + len)
    {
        fprintf(stderr,"ifname Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    p = malloc(IFNAMSIZ + 1);
    memcpy(p,&element->data,IFNAMSIZ + 1);
    params->ifname = (const char *)p;
    counter += len;
    /* ssid */
    len = sizeof(element->len) + MAX_SSID_LEN;
    if(pdu_size < counter + len)
    {
        fprintf(stderr,"ssid Error,%s:%d\n",__FILE__,__LINE__);
        goto err;  
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    p = malloc(MAX_SSID_LEN);
    memcpy(p,&element->data,MAX_SSID_LEN);
    params->ssid = (const u8 *)p;
    counter += len;
    /* ssid_len */
    len = sizeof(element->len) + sizeof(params->ssid_len);
    if(pdu_size < counter + len)
    {
        fprintf(stderr,"ssid_len Error,%s:%d\n",__FILE__,__LINE__);
        goto err;  
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(&params->ssid_len,&element->data,sizeof(params->ssid_len));
    counter += len;
    /* own_addr */
    len = sizeof(element->len) + ETH_ALEN;
    if(pdu_size < counter + len)
    {
        fprintf(stderr,"own_addr Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    params->own_addr = malloc(ETH_ALEN);
    memcpy(params->own_addr,&element->data,ETH_ALEN);

    return 0;
err:
    return -1;
}

int wpa_init_params_format(char * pdu, int *p_size,struct wpa_init_params *params)
{
    struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int i = 0;
    int len;
    int pdu_size = *p_size;
     
    if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu) || params == NULL)
    {
        fprintf(stderr,"wpa_init_params_format args Error,%s:%d\n",__FILE__,__LINE__); 
        goto err;   
    }

    wpdu = (struct wiflow_pdu*)pdu;
    wpdu->type = I802_INIT_PARAMS;
    counter += sizeof(struct wiflow_pdu);
    /* bssid */
    len = sizeof(element->len) + ETH_ALEN;
    if(pdu_size < counter + len)
    {
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    element->len = ETH_ALEN;
    if(params->bssid == NULL)
    {
        memset(&element->data,0,element->len);
    }
    else
    {
        memcpy(&element->data,params->bssid,element->len);
    }
    counter += len;
    /* ifname */
    len = sizeof(element->len) + IFNAMSIZ + 1;
    if(pdu_size < counter + len)
    {
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    element->len = IFNAMSIZ + 1;
    memcpy(&element->data,params->ifname,element->len);
    counter += len;
    /* ssid */
    len = sizeof(element->len) + MAX_SSID_LEN;
    if(pdu_size < counter + len)
    {
        goto err;  
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    element->len = MAX_SSID_LEN;
    memcpy(&element->data,params->ssid,element->len);
    counter += len;
    /* ssid_len */
    len = sizeof(element->len) + sizeof(params->ssid_len);
    if(pdu_size < counter + len)
    {
        goto err;  
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    element->len = sizeof(params->ssid_len);
    memcpy(&element->data,&params->ssid_len,element->len);
    counter += len;
    /* own_addr */
    len = sizeof(element->len) + ETH_ALEN;
    if(pdu_size < counter + len)
    {
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    element->len = ETH_ALEN;
    memcpy(&element->data,params->own_addr,ETH_ALEN);
    counter += len;

    *p_size = counter;
    return 0; 
err:
    return -1;
}
/*
struct i802_bss {
	struct wpa_driver_nl80211_data *drv;//NOT used
	struct i802_bss *next;//multi-record flag
	int ifindex;
	char ifname[IFNAMSIZ + 1];
	char brname[IFNAMSIZ];
	unsigned int beacon_set:1;
	unsigned int added_if_into_bridge:1;
	unsigned int added_bridge:1;
	unsigned int in_deinit:1;

	u8 addr[ETH_ALEN];

	int freq;

	void *ctx;//NOT used
	struct nl_handle *nl_preq, *nl_mgmt;//NOT used
	struct nl_cb *nl_cb;//NOT used

	struct nl80211_wiphy_data *wiphy_data;//NOT used
	struct dl_list wiphy_list;//NOT used
};
*/
struct i802_bss_pdu 
{
	int ifindex;
	char ifname[IFNAMSIZ + 1];
	char brname[IFNAMSIZ];
	unsigned int beacon_set:1;
	unsigned int added_if_into_bridge:1;
	unsigned int added_bridge:1;
	unsigned int in_deinit:1;

	u8 addr[ETH_ALEN];

	int freq;
};
int i802_bss_parser(char * pdu, int pdu_size,struct i802_bss *bss)
{
    struct i802_bss_pdu *p = (struct i802_bss_pdu *)pdu;
    bss->ifindex = p->ifindex;
    memcpy(bss->ifname,p->ifname,IFNAMSIZ + 1);
    memcpy(bss->brname,p->brname,IFNAMSIZ + 1);
    bss->beacon_set = p->beacon_set;
    bss->added_if_into_bridge = p->added_if_into_bridge;
    bss->added_bridge = p->added_bridge;
    bss->in_deinit = p->in_deinit;
    memcpy(bss->addr,p->addr,ETH_ALEN);
    bss->freq = p->freq;
    return 0;   
}

int i802_bss_format(char * pdu, int *p_size,struct i802_bss *p)
{
    int pdu_size = *p_size;
    struct i802_bss_pdu *bss = (struct i802_bss_pdu *)pdu;
    bss->ifindex = p->ifindex;
    memcpy(bss->ifname,p->ifname,IFNAMSIZ + 1);
    memcpy(bss->brname,p->brname,IFNAMSIZ + 1);
    bss->beacon_set = p->beacon_set;
    bss->added_if_into_bridge = p->added_if_into_bridge;
    bss->added_bridge = p->added_bridge;
    bss->in_deinit = p->in_deinit;
    memcpy(bss->addr,p->addr,ETH_ALEN);
    bss->freq = p->freq;
    *p_size = sizeof(struct i802_bss_pdu);
    return 0;    
}



