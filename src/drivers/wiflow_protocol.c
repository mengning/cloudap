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

int wiflow_pdu_format(char * pdu, int *p_size,int type)
{
    struct wiflow_pdu *wpdu;
    int pdu_size = *p_size;
     
    if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wiflow_pdu_format args Error,%s:%d\n",__FILE__,__LINE__); 
        goto err;   
    }

    wpdu = (struct wiflow_pdu*)pdu;
    wpdu->type = type;
    return 0;
err:
    return -1;   
}
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
    int len;
    char * p;
    if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu) || params == NULL)
    {
        fprintf(stderr,"wpa_init_params_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,pdu_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
    if(wpdu->type != WIFLOW_INIT_PARAMS_RESPONSE)
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
    int len;
    int pdu_size = *p_size;
     
    if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu) || params == NULL)
    {
        fprintf(stderr,"wpa_init_params_format args Error,%s:%d\n",__FILE__,__LINE__); 
        goto err;   
    }

    wpdu = (struct wiflow_pdu*)pdu;
    wpdu->type = WIFLOW_INIT_PARAMS_RESPONSE;
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

int wpa_ieee80211_mgmt_format(char *pdu, int *p_size, const u8 *data, size_t data_len, int encrypt)
{
	struct wiflow_pdu *wpdu;
	struct ieee80211_mgmt *mgmt = data;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
    int pdu_size = *p_size;

	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu) || data== NULL)
    {
        fprintf(stderr,"wpa_ieee80211_mgmt_format args Error,%s:%d\n",__FILE__,__LINE__); 
        goto err;   
    }
	wpdu = (struct wiflow_pdu*)pdu;
    wpdu->type = WIFLOW_NL80211_SEND_FRAME_REQUEST;
	counter += sizeof(struct wiflow_pdu);
	/*struct ieee80211_mgmt *mgmt*/
	len = sizeof(element->len) + sizeof(struct ieee80211_mgmt);
	if(pdu_size < counter + len)
	{
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(struct ieee80211_mgmt);
	memcpy(&element->data,mgmt,element->len);
	counter += len;
	/*data_len*/
	len = sizeof(element->len) + sizeof(data_len);
	if(pdu_size < counter + len)
	{
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(data_len);
	memcpy(&element->data,&data_len,element->len);
	counter += len;
	/*encrypt*/
	len = sizeof(element->len) + sizeof(int);
	if(pdu_size < counter + len)
	{
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(int);
	memcpy(&element->data,&encrypt,element->len);
	counter += len;
	*p_size = counter;
	return 0;
err:
	return -1;
}

int wpa_i802_set_wds_sta_format(char *pdu, int *p_size, const u8 *addr, int aid, int val, const char *bridge_ifname)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
    int pdu_size = *p_size;
	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_i802_set_wds_sta_format args Error,%s:%d\n",__FILE__,__LINE__); 
        goto err;   
    }
	wpdu = (struct wiflow_pdu*)pdu;
    wpdu->type = WIFLOW_NL80211_I802_SET_WDS_STA_REQUEST;
	counter += sizeof(struct wiflow_pdu);
	/*addr*/
	len = sizeof(element->len) + ETH_ALEN;
	if(pdu_size < counter + len)
	{
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = ETH_ALEN;
	memcpy(&element->data,addr,element->len);
	counter += len;
	/*aid*/
	len = sizeof(element->len) + sizeof(int);
	if(pdu_size < counter + len)
	{
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(int);
	memcpy(&element->data,&aid,element->len);
	counter += len;
	/*val*/
	len = sizeof(element->len) + sizeof(int);
	if(pdu_size < counter + len)
	{
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(int);
	memcpy(&element->data,&val,element->len);
	counter += len;
	/*bridge_ifname*/
	len = sizeof(element->len) + IFNAMSIZ + 1;
	if(pdu_size < counter + len)
	{
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = IFNAMSIZ + 1;
	memcpy(&element->data,bridge_ifname,element->len);
	counter += len;
	*p_size = counter;
	return 0;
err:
	return -1;
}

int wpa_sta_add_format(char *pdu, int *p_size,struct hostapd_sta_add_params *params)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
	struct ieee80211_ht_capabilities *ht_capab; 
    int counter = 0;
    int len;
    int pdu_size = *p_size;
	ht_capab = params->ht_capabilities;

	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu) || params== NULL)
    {
        fprintf(stderr,"wpa_sta_add_format args Error,%s:%d\n",__FILE__,__LINE__); 
        goto err;   
    }
	wpdu = (struct wiflow_pdu*)pdu;
    wpdu->type = WIFLOW_NL80211_STA_ADD_REQUEST;
	counter += sizeof(struct wiflow_pdu);
	/*addr*/
	len = sizeof(element->len) + ETH_ALEN;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"addr Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = ETH_ALEN;
	memcpy(&element->data,params->addr,element->len);
	counter += len;
	/*aid*/
	len = sizeof(element->len) + sizeof(params->aid);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"aid Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->aid);
	memcpy(&element->data,&params->aid,element->len);
	counter += len;
	/*capability*/
	len = sizeof(element->len) + sizeof(params->capability);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"capability Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->capability);
	memcpy(&element->data,&params->capability,element->len);
	counter += len;
	/*supp_rates*/
	len = sizeof(element->len) + WLAN_SUPP_RATES_MAX;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"supp_rates Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = WLAN_SUPP_RATES_MAX;
	memcpy(&element->data,params->supp_rates,element->len);
	counter += len;
	/*supp_rates_len*/
	len = sizeof(element->len) + sizeof(params->supp_rates_len);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"supp_rate_len Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->supp_rates_len);
	memcpy(&element->data,&params->supp_rates_len,element->len);
	counter += len;
	/*listen_interval*/
	len = sizeof(element->len) + sizeof(params->listen_interval);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"listen Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->listen_interval);
	memcpy(&element->data,&params->listen_interval,element->len);
	counter += len;
	/*ht_capabilities*/
	len = sizeof(element->len) + sizeof(ht_capab);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"ht_capabilities Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(ht_capab);
	memcpy(&element->data,ht_capab,element->len);
	counter += len;
	/*flags*/
	len = sizeof(element->len) + sizeof(params->flags);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"flags Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->flags);
	memcpy(&element->data,&params->flags,element->len);
	counter += len;
	/*qosinfo*/
	len = sizeof(element->len) + sizeof(params->qosinfo);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"qosinfo Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->qosinfo);
	memcpy(&element->data,&params->qosinfo,element->len);
	counter += len;
	
	*p_size = counter;
	return 0;
err:
	return -1;
}

int wpa_if_add_format(char *pdu, int *p_size, enum wpa_driver_if_type type, const char *ifname, const u8 *addr, 
							void *bss_ctx, void **drv_priv, char *force_ifname, u8 *if_addr)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
    int pdu_size = *p_size;

	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_if_add_format args Error,%s:%d\n",__FILE__,__LINE__); 
        goto err;   
    }
	wpdu = (struct wiflow_pdu*)pdu;
	if(bss_ctx == NULL && drv_priv == NULL)
    	wpdu->type = WIFLOW_NL80211_IF_ADD_REQUEST1;
	else
		wpdu->type = WIFLOW_NL80211_IF_ADD_REQUEST2;
	counter += sizeof(struct wiflow_pdu);
	/*type*/
	len = sizeof(element->len) + sizeof(int);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"type Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(int);
	memcpy(&element->data,type,element->len);
	counter += len;
	/*ifname*/
	len = sizeof(element->len) + IFNAMSIZ + 1;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"ifname Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = IFNAMSIZ + 1;
	memcpy(&element->data,ifname,element->len);
	counter += len;
	/*addr*/
	len = sizeof(element->len) + ETH_ALEN;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"addr Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = ETH_ALEN;
	memcpy(&element->data,addr,element->len);
	counter += len;
	/*force_name*/
	len = sizeof(element->len) + IFNAMSIZ;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"force_name Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = IFNAMSIZ;
	memcpy(&element->data,force_ifname,element->len);
	counter += len;
	/*if_add*/
	len = sizeof(element->len) + ETH_ALEN;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"if_add Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = ETH_ALEN;
	memcpy(&element->data,if_addr,element->len);
	counter += len;

	*p_size = counter;
	return 0;
err:
	return -1;
}

int wpa_set_freq_format(char * pdu, int * p_size, struct hostapd_freq_params * freq)
{
	
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
    int pdu_size = *p_size;
	
	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu) || freq == NULL)
    {
        fprintf(stderr,"wpa_set_freq_format args Error,%s:%d\n",__FILE__,__LINE__); 
        goto err;   
    }
	wpdu = (struct wiflow_pdu*)pdu;
	wpdu->type = WIFLOW_NL80211_SET_FREQ_REQUEST;
	counter += sizeof(struct wiflow_pdu);
	/*freq*/
	len = sizeof(element->len) + sizeof(struct hostapd_freq_params);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"freq Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(struct hostapd_freq_params);
	memcpy(&element->data,freq,element->len);
	counter += len;

	*p_size = counter;
	return 0;
err:
	return -1;
}

int wpa_sta_set_flags_format(char * pdu,int * p_size,,const u8 * addr,int total_flags,int flags_or,int flags_and)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
    int pdu_size = *p_size;
	int int_size = sizeof(int);

	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu) || addr== NULL)
    {
        fprintf(stderr,"wpa_sta_set_flags_format args Error,%s:%d\n",__FILE__,__LINE__); 
        goto err;   
    }
	wpdu = (struct wiflow_pdu*)pdu;
	wpdu->type = WIFLOW_NL80211_STA_SET_FLAGS_REQUEST;
	counter += sizeof(struct wiflow_pdu);
	/*addr*/
	len = sizeof(element->len) + ETH_ALEN;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"addr Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = ETH_ALEN;
	memcpy(&element->data,addr,element->len);
	counter += len;
	/*total_flags*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"total_flags Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = int_size;
	memcpy(&element->data,&total_flags,element->len);
	counter += len;
	/*flags_or*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"flags_or Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = int_size;
	memcpy(&element->data,&flags_or,element->len);
	counter += len;
	/*flags_and*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"flags_and Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = int_size;
	memcpy(&element->data,&flags_and,element->len);
	counter += len;

	*p_size = counter;
	return 0;
err:
	return -1;
}

int wpa_send_action_format(char * pdu,int * p_size, unsigned int freq, unsigned int wait_time, const u8 * dst, const u8 * data,size_t data_len)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
    int pdu_size = *p_size;

	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_send_action_format args Error,%s:%d\n",__FILE__,__LINE__); 
        goto err;   
    }
	wpdu = (struct wiflow_pdu*)pdu;
	wpdu->type = WIFLOW_NL80211_SEND_FRAME_REQUEST;
	counter += sizeof(struct wiflow_pdu);
	/*freq*/
	len = sizeof(element->len) + sizeof(freq);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"freq Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(freq);
	memcpy(&element->data,&freq,element->len);
	counter += len;
	/*wait_time*/
	len = sizeof(element->len) + sizeof(wait_time);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"wait_time Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(wait_time);
	memcpy(&element->data,&wait_time,element->len);
	counter += len;
	/*dst*/
	len = sizeof(element->len) + ETH_ALEN;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"dst Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = ETH_ALEN;
	memcpy(&element->data,dst,element->len);
	counter += len;
	/*data*/
	len = sizeof(element->len) + sizeof(data_len * sizeof(data_len));
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"data Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(data_len * sizeof(data_len));
	memcpy(&element->data,data,element->len);
	counter += len;
	/*data_len*/
	len = sizeof(element->len) + sizeof(data_len);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"data_len Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(data_len);
	memcpy(&element->data,&data_len,element->len);
	counter += len;
	*p_size = counter;
	return 0;
err:
	return -1;
}

int wpa_set_tx_queue_params_format(char * pdu, int * p_size, int queue, int aifs, int cw_min, int cw_max, int burst_time)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
    int pdu_size = *p_size;
	int int_size = sizeof(int);

	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_send_action_format args Error,%s:%d\n",__FILE__,__LINE__); 
        goto err;   
    }
	wpdu = (struct wiflow_pdu*)pdu;
	wpdu->type = WIFLOW_NL80211_SET_TX_QUEUE_PARAMS_REQUEST;
	counter += sizeof(struct wiflow_pdu);
	/*queue*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"queue Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = int_size;
	memcpy(&element->data,&queue,element->len);
	counter += len;
	/*aifs*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"aifs Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = int_size;
	memcpy(&element->data,&aifs,element->len);
	counter += len;
	/*cw_min*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"cw_min Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = int_size;
	memcpy(&element->data,&cw_min,element->len);
	counter += len;
	/*cw_max*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"cw_max Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = int_size;
	memcpy(&element->data,&cw_max,element->len);
	counter += len;
	/*burst_time*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"burst_time Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = int_size;
	memcpy(&element->data,&burst_time,element->len);
	counter += len;

	*p_size = counter;
	return 0;
err:
	return -1;
}
