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

#include "common/ieee802_11_defs.h"
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
    wpdu->type = WIFLOW_INIT_PARAMS_REQUEST;
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

int wpa_ieee80211_mgmt_parser(char * pdu,int p_size, struct ieee80211_mgmt *mgmt, size_t *data_len, int *encrypt)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
    size_t datalen;
	int p_encrypt;
	
	if(pdu == NULL || p_size < sizeof(struct wiflow_pdu) || mgmt == NULL)
    {
        fprintf(stderr,"wpa_init_params_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,p_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
    if(wpdu->type != WIFLOW_NL80211_SEND_FRAME_REQUEST)
    {
        fprintf(stderr,"wpdu->type Error,%s:%d\n",__FILE__,__LINE__);
        goto err;   
    }
    counter += sizeof(struct wiflow_pdu);
	/*struct ieee80211_mgmt *mgmt*/
	len = sizeof(element->len) + sizeof(mgmt);
	if(p_size < counter + len)
	{
		 fprintf(stderr,"ieee80211_mgmt Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(mgmt,&element->data,sizeof(mgmt));
	counter += len;
	/*data_len*/
	len = sizeof(element->len) + sizeof(datalen);
	if(p_size < counter + len)
    {
        fprintf(stderr,"data_len Error,%s:%d\n",__FILE__,__LINE__);
        goto err;  
    }
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&datalen,&element->data,sizeof(datalen));
	*data_len = datalen;
	/*encrypt*/
	len = sizeof(element->len) + sizeof(p_encrypt);
	if(p_size < counter + len)
    {
        fprintf(stderr,"encrypt Error,%s:%d\n",__FILE__,__LINE__);
        goto err;  
    }
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&p_encrypt,&element->data,sizeof(p_encrypt));
	*encrypt = p_encrypt;
	return 0;
err:
	return -1;
}

int wpa_i802_set_wds_sta_parser(char *pdu, int p_size,u8 *addr, int *aid, int *val,char *bridge_ifname)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
	int t_aid,t_val;
	char *p;
	
	if(pdu == NULL || p_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_i802_set_wds_sta_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,p_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
    if(wpdu->type != WIFLOW_NL80211_I802_SET_WDS_STA_REQUEST)
    {
        fprintf(stderr,"wpdu->type Error,%s:%d\n",__FILE__,__LINE__);
        goto err;   
    }
    counter += sizeof(struct wiflow_pdu);
	/*addr*/
	len = sizeof(element->len) + ETH_ALEN;
	if(p_size < counter + len)
	{
		fprintf(stderr,"set_wds_sta addr Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	p = malloc(ETH_ALEN);
	memcpy(p, &element->data, ETH_ALEN);
	if(*p == 0)
	{
		addr = NULL;
		free(p);
		p = NULL;
	}
	else 
	{
		addr = (u8 *)p;
	}
	
	counter += len;
	/*aid*/
	len = sizeof(element->len) + sizeof(int);
	if(p_size < counter + len)
	{
		fprintf(stderr,"aid Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&t_aid, &element->data, sizeof(int));
	*aid = t_aid;
	counter += len;
	/*val*/
	len = sizeof(element->len) + sizeof(int);
	if(p_size < counter + len)
	{
		fprintf(stderr,"val Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&t_val, &element->data, sizeof(int));
	*val= t_val;
	counter += len;
	/*bridge_ifname*/
	len = sizeof(element->len) + IFNAMSIZ + 1;
	if(p_size < counter + len)
	{
		fprintf(stderr,"bridge_ifname Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	p = malloc(IFNAMSIZ + 1);
	memcpy(p, &element->data, IFNAMSIZ + 1);
	if(*p == 0)
	{
		bridge_ifname= NULL;
		free(p);
		p = NULL;
	}
	else 
	{
		bridge_ifname = (u8 *)p;
	}
	
	return 0;
err:
	return -1;
}

int wpa_sta_add_parser(char * pdu,int p_size,struct hostapd_sta_add_params * params)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
	struct ieee80211_ht_capabilities *ht_capab;
    int counter = 0;
    int len;
	char *p;

	if(pdu == NULL || p_size < sizeof(struct wiflow_pdu) || params == NULL)
    {
        fprintf(stderr,"wpa_sta_add_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,p_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
    if(wpdu->type != WIFLOW_NL80211_STA_ADD_REQUEST)
    {
        fprintf(stderr,"wpdu->type Error,%s:%d\n",__FILE__,__LINE__);
        goto err;   
    }
    counter += sizeof(struct wiflow_pdu);
	/*addr*/
	len = sizeof(element->len) + ETH_ALEN;
    if(p_size < counter + len)
    {
        fprintf(stderr,"addr Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    p = malloc(ETH_ALEN);
    memcpy(p,&element->data,ETH_ALEN);
	if(*p == 0)
	{
		params->addr = NULL;
		free(p);
		p = NULL;
	}
	else 
	{
		params->addr = (u8 *)p;
	}
    counter += len;
	/*aid*/
	len = sizeof(element->len) + sizeof(params->aid);
    if(p_size < counter + len)
    {
        fprintf(stderr,"aid Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(&params->aid,&element->data,sizeof(params->aid));
    counter += len;
	/*capability*/
	len = sizeof(element->len) + sizeof(params->capability);
    if(p_size < counter + len)
    {
        fprintf(stderr,"capability Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(&params->capability,&element->data,sizeof(params->capability));
    counter += len;
	/*supp_rates*/
	len = sizeof(element->len) + 32;
    if(p_size < counter + len)
    {
        fprintf(stderr,"supp_rates Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    p = malloc(WLAN_SUPP_RATES_MAX);
    memcpy(p,&element->data,32);
	if(*p == 0)
	{
		params->supp_rates = NULL;
		free(p);
		p = NULL;
	}
	else 
	{
		params->supp_rates= (u8 *)p;
	}
    
    counter += len;
	/*supp_rates_len*/
	len = sizeof(element->len) + sizeof(params->supp_rates_len);
    if(p_size < counter + len)
    {
        fprintf(stderr,"supp_rates_len Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(&params->supp_rates_len,&element->data,sizeof(params->supp_rates_len));
    counter += len;
	/*listen_interval*/
	len = sizeof(element->len) + sizeof(params->listen_interval);
    if(p_size < counter + len)
    {
        fprintf(stderr,"listen_interval Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(&params->listen_interval,&element->data,sizeof(params->listen_interval));
    counter += len;
	/*ht_capabilities*/
	len = sizeof(element->len) + sizeof(params->ht_capabilities);
    if(p_size < counter + len)
    {
        fprintf(stderr,"ht_capabilities Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    p = malloc(sizeof(ht_capab));
    memcpy(p,&element->data,sizeof(ht_capab));
    params->ht_capabilities=  (struct ieee80211_ht_capabilities *)p;
    counter += len;
	/*flag*/
	len = sizeof(element->len) + sizeof(params->flags);
    if(p_size < counter + len)
    {
        fprintf(stderr,"flag Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(&params->flags,&element->data,sizeof(params->flags));
    counter += len;
	/*qosinfo*/
	len = sizeof(element->len) + sizeof(params->qosinfo);
    if(p_size < counter + len)
    {
        fprintf(stderr,"qosinfo Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(&params->qosinfo,&element->data,sizeof(params->qosinfo));

	return 0;
err:
	return -1;
}

int wpa_if_add_parser(char *pdu, int p_size, struct wpa_function_params *func_params)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
	char *p;

	if(pdu == NULL || p_size < sizeof(struct wiflow_pdu) ||  func_params == NULL)
    {
        fprintf(stderr,"wpa_sta_add_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,p_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
    if(wpdu->type != WIFLOW_NL80211_IF_ADD_REQUEST1 || wpdu->type != WIFLOW_NL80211_IF_ADD_REQUEST2 )
    {
        fprintf(stderr,"wpdu->type Error,%s:%d\n",__FILE__,__LINE__);
        goto err;	
    }
	counter += sizeof(struct wiflow_pdu);
	/*type*/
	len = sizeof(element->len) + sizeof(int);
    if(p_size < counter + len)
    {
        fprintf(stderr,"type Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(&func_params->type,&element->data,sizeof(int));
    counter += len;
	/*ifname*/
	len = sizeof(element->len) + IFNAMSIZ + 1;
    if(p_size < counter + len)
    {
        fprintf(stderr,"ifname Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    p = malloc(IFNAMSIZ + 1);
    memcpy(p,&element->data,IFNAMSIZ + 1);
	if(*p == 0)
	{
		func_params->ifname = NULL;
		free(p);
		p = NULL;
	}
	else 
	{
		func_params->ifname = (const char *)p;
	}
   
    counter += len;
	/*addr*/
	len = sizeof(element->len) + ETH_ALEN;
    if(p_size < counter + len)
    {
        fprintf(stderr,"addr Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    p = malloc(ETH_ALEN);
    memcpy(p,&element->data,ETH_ALEN);
	if(*p == 0)
	{
		func_params->addr = NULL;
		free(p);
		p = NULL;
	}
	else 
	{
		func_params->addr = (u8 *)p;
	}
    
    counter += len;
	/*force_name*/
	len = sizeof(element->len) + IFNAMSIZ;
    if(p_size < counter + len)
    {
        fprintf(stderr,"force_fname Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    p = malloc(IFNAMSIZ);
    memcpy(p,&element->data,IFNAMSIZ);
    func_params->force_ifname= (const char *)p;
    counter += len;
	/*if_addr*/
	len = sizeof(element->len) + ETH_ALEN;
    if(p_size < counter + len)
    {
        fprintf(stderr,"if_addr Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    p = malloc(ETH_ALEN);
    memcpy(p,&element->data,ETH_ALEN);
    func_params->if_addr= (u8 *)p;
	
	return 0;
err:
	return -1;
}

int wpa_set_freq_parser(char * pdu, int p_size, struct hostapd_freq_params * freq)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
	char *p;

	if(pdu == NULL || p_size < sizeof(struct wiflow_pdu) || freq == NULL)
    {
        fprintf(stderr,"wpa_set_freq_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,p_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
	if(wpdu->type != WIFLOW_NL80211_SET_FREQ_REQUEST)
	{
		fprintf(stderr,"wpdu->type Error,%s:%d\n",__FILE__,__LINE__);
        goto err;	
	}
	counter += sizeof(struct wiflow_pdu);
	/*freq*/
	len = sizeof(element->len) + sizeof(struct hostapd_freq_params);
	if(p_size < counter + len)
    {
        fprintf(stderr,"freq Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    p = malloc(sizeof(struct hostapd_freq_params));
    memcpy(p,&element->data,sizeof(struct hostapd_freq_params));
    freq = (struct hostapd_freq_params *)p;
	return 0;
err:
	return -1;
}


int wpa_sta_set_flags_parser(char *pdu, int p_size, u8 *addr, int* total_flags,
					    int* flags_or, int* flags_and)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
	char *p;
	int int_size = sizeof(int);

	if(pdu == NULL || p_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_sta_set_flags_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,p_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
	if(wpdu->type != WIFLOW_NL80211_STA_SET_FLAGS_REQUEST)
	{
		fprintf(stderr,"wpdu->type Error,%s:%d\n",__FILE__,__LINE__);
        goto err;	
	}
	counter += sizeof(struct wiflow_pdu);
	/*addr*/
	len = sizeof(element->len) + ETH_ALEN;
    if(p_size < counter + len)
    {
        fprintf(stderr,"addr Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    p = malloc(ETH_ALEN);
    memcpy(p,&element->data,ETH_ALEN);
	if(*p == 0)
	{
		addr = NULL;
		free(p);
		p = NULL;
	}
	else 
	{
		addr = (u8 *)p;
	}
    
    counter += len;
	/*total_flags*/
	len = sizeof(element->len) + int_size;
    if(p_size < counter + len)
    {
        fprintf(stderr,"total_flags Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(total_flags,&element->data,int_size);
    counter += len;
	/*flags_or*/
	len = sizeof(element->len) + int_size;
    if(p_size < counter + len)
    {
        fprintf(stderr,"flags_or Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(flags_or,&element->data,int_size);
    counter += len;
	/*flags_and*/
	len = sizeof(element->len) + int_size;
    if(p_size < counter + len)
    {
        fprintf(stderr,"flags_and Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(flags_and,&element->data,int_size);
	
	return 0;
err:
	return -1;
}

int wpa_send_action_parser(char * pdu,int p_size,unsigned int *freq,unsigned int *wait_time,
									const u8 * dst,const u8 * data,size_t *data_len)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
	char *p;

	if(pdu == NULL || p_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_send_action_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,p_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
	if(wpdu->type != WIFLOW_NL80211_SEND_ACTION_REQUEST)
	{
		fprintf(stderr,"wpdu->type Error,%s:%d\n",__FILE__,__LINE__);
        goto err;	
	}
	counter += sizeof(struct wiflow_pdu);
	/*freq*/
	len = sizeof(element->len) + sizeof(freq);
	if(p_size < counter + len)
	{
		fprintf(stderr,"freq Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(freq,&element->data,sizeof(freq));
	counter += len;
	/*wait_time*/
	len = sizeof(element->len) + sizeof(wait_time);
	if(p_size < counter + len)
	{
		fprintf(stderr,"wait_time Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(wait_time,&element->data,sizeof(wait_time));
	counter += len;
	/*dst*/
	len = sizeof(element->len) + ETH_ALEN;
	if(p_size < counter + len)
	{
		fprintf(stderr,"dst Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	p = malloc(ETH_ALEN);
	memcpy(p,&element->data,ETH_ALEN);
	if(*p == 0)
	{
		dst = NULL;
		free(p);
		p = NULL;
	}
	else 
	{
		dst = (u8 *)p;
	}
	counter += len;
	/*data*/
	len = sizeof(element->len) + *data_len;
	if(p_size < counter + len)
	{
		fprintf(stderr,"data Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	p = malloc(*data_len);
	memcpy(p,&element->data,*data_len);
	if(*p == 0)
	{
		data= NULL;
		free(p);
		p = NULL;
	}
	else 
	{
		data= (u8 *)p;
	}
	counter += len;
	/*data_len*/
	len = sizeof(element->len) + sizeof(data_len);
	if(p_size < counter + len)
	{
		fprintf(stderr,"data_len Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(data_len,&element->data,sizeof(data_len));
	return 0;
err: return -1;
}

int wpa_set_tx_queue_params_parser(char * pdu,int p_size,struct wpa_set_tx_queue_params * tx_params)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
	char *p;
	int int_size = sizeof(int);
	
	if(pdu == NULL || p_size < sizeof(struct wiflow_pdu) || tx_params == NULL)
    {
        fprintf(stderr,"wpa_set_freq_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,p_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
	if(wpdu->type != WIFLOW_NL80211_SET_TX_QUEUE_PARAMS_REQUEST)
	{
		fprintf(stderr,"wpdu->type Error,%s:%d\n",__FILE__,__LINE__);
        goto err;	
	}
	counter += sizeof(struct wiflow_pdu);
	/*queue*/
	len = sizeof(element->len) + int_size;
	if(p_size < counter + len)
    {
        fprintf(stderr,"queue Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(&tx_params->queue,&element->data,int_size);
    counter += len;
	/*aifs*/
	len = sizeof(element->len) + int_size;
	if(p_size < counter + len)
    {
        fprintf(stderr,"tx_params Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(&tx_params->aifs,&element->data,int_size);
    counter += len;
	/*cw_min*/
	len = sizeof(element->len) + int_size;
	if(p_size < counter + len)
    {
        fprintf(stderr,"cw_min Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(&tx_params->cw_min,&element->data,int_size);
    counter += len;
	/*cw_max*/
	len = sizeof(element->len) + int_size;
	if(p_size < counter + len)
    {
        fprintf(stderr,"cw_max Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(&tx_params->cw_max,&element->data,int_size);
    counter += len;
	/*burst_time*/
	len = sizeof(element->len) + int_size;
	if(p_size < counter + len)
    {
        fprintf(stderr,"burst_time Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(&tx_params->burst_time,&element->data,int_size);
	return 0;
err:
	return -1;
}

int wpa_scan2_parser(char * pdu,int p_size,struct wpa_driver_scan_params * params)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
	char *p;

	if(pdu == NULL || p_size < sizeof(struct wiflow_pdu) || params == NULL)
    {
        fprintf(stderr,"wpa_scan2_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,p_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
	if(wpdu->type != WIFLOW_NL80211_SCAN2_REQUEST)
	{
		fprintf(stderr,"wpdu->type Error,%s:%d\n",__FILE__,__LINE__);
        goto err;	
	}
	counter += sizeof(struct wiflow_pdu);
	element = (struct wiflow_pdu_element *)(pdu + counter);
	p = malloc(element->len);
	memcpy(p, &element->data, element->len);
	params->freqs = (int *)p;
	return 0;
err:
	return -1;
}

int wpa_sta_deauth_parser(char * pdu,int p_size, const u8 * addr,int *reason)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
	char *p;

	if(pdu == NULL || p_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_sta_deauth_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,p_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
	if(wpdu->type != WIFLOW_NL80211_STA_DEAUTH_REQUEST)
	{
		fprintf(stderr,"wpdu->type Error,%s:%d\n",__FILE__,__LINE__);
        goto err;	
	}
	counter += sizeof(struct wiflow_pdu);
	/*addr*/
	len = sizeof(element->len) + ETH_ALEN;
	if(p_size < counter + len)
	{
		fprintf(stderr,"addr Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	p = malloc(ETH_ALEN);
	memcpy(p,&element->data,ETH_ALEN);
	if(*p == 0)
	{
		addr = NULL;
		free(p);
		p = NULL;
	}
	else 
	{
		addr = (u8 *)p;
	}
	counter += len;
	/*reason*/
	len = sizeof(element->len) + sizeof(int);
	if(p_size < counter + len)
    {
        fprintf(stderr,"reason Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(reason,&element->data,sizeof(int));
	return 0;
err:
	return -1;
}

int wpa_set_key_parser(char * pdu,int p_size,struct wpa_set_key_params * key_params)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
	char *p;
	int int_size = sizeof(int);

	if(pdu == NULL || p_size < sizeof(struct wiflow_pdu) || key_params == NULL)
    {
        fprintf(stderr,"wpa_set_key_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,p_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
	if(wpdu->type != WIFLOW_NL80211_SET_KEY_REQUEST)
	{
		fprintf(stderr,"wpdu->type Error,%s:%d\n",__FILE__,__LINE__);
        goto err;	
	}
	counter += sizeof(struct wiflow_pdu);
	/*alg*/
	len = sizeof(element->len) + int_size;
	if(p_size < counter + len)
    {
        fprintf(stderr,"alg Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(&key_params->alg,&element->data,int_size);
	counter += len;
	/*addr*/
	len = sizeof(element->len) + ETH_ALEN;
	if(p_size < counter + len)
	{
		fprintf(stderr,"addr Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	p = malloc(ETH_ALEN);
	memcpy(p,&element->data,element->len);
	if(*p == 0)
	{
		key_params->addr = NULL;
		free(p);
		p = NULL;
	}
	else
	{
		key_params->addr = (u8 *)p;
	}
	counter += len;
	/*key_idx*/
	len = sizeof(element->len) + int_size;
	if(p_size < counter + len)
    {
        fprintf(stderr,"key_idx Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(&key_params->key_idx,&element->data,int_size);
	counter += len;
	/*set_tx*/
	len = sizeof(element->len) + int_size;
	if(p_size < counter + len)
    {
        fprintf(stderr,"set_tx Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(&key_params->set_tx,&element->data,int_size);
	counter += len;
	/*seq_len*/
	len = sizeof(element->len) + sizeof(size_t);
	if(p_size < counter + len)
    {
        fprintf(stderr,"seq_len Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(&key_params->seq_len,&element->data,sizeof(size_t));
	counter += len;
	/*seq*/
	len = sizeof(element->len) + key_params->seq_len;
	if(p_size < counter + len)
	{
		fprintf(stderr,"seq Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	p = malloc(key_params->seq_len);
	memcpy(p,&element->data,key_params->seq_len);
	if(*p == 0) 
	{
		key_params->seq = NULL;
		free(p);
		p = NULL;
	}
	else
		key_params->seq = (u8 *)p;
	counter += len;
	/*key_len*/
	len = sizeof(element->len) + sizeof(size_t);
	if(p_size < counter + len)
    {
        fprintf(stderr,"key_len Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(&key_params->key_len,&element->data,sizeof(size_t));
	counter += len;
	/*key*/
	len = sizeof(element->len) + key_params->key_len;
	if(p_size < counter + len)
	{
		fprintf(stderr,"key Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	p = malloc(key_params->key_len);
	memcpy(p,&element->data,key_params->key_len);
	if(*p == 0) 
	{
		key_params->key= NULL;
		free(p);
		p = NULL;
	}
	else
		key_params->key= (u8 *)p;

	return 0;
err:
	return -1;
}

int wpa_send_mlme_parser(char * pdu,int p_size,const u8 * data, size_t * data_len,int * noack)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
	char *p;

	if(pdu == NULL || p_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_sta_deauth_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,p_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
	if(wpdu->type != WIFLOW_NL80211_SEND_MLME_REQUEST)
	{
		fprintf(stderr,"wpdu->type Error,%s:%d\n",__FILE__,__LINE__);
        goto err;	
	}
	counter += sizeof(struct wiflow_pdu);
	/*data_len*/
	len = sizeof(element->len) + sizeof(data_len);
	if(p_size < counter + len)
    {
        fprintf(stderr,"data_len Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(data_len,&element->data,sizeof(data_len));
	/*data*/
	len = sizeof(element->len) + *data_len;
	if(p_size < counter + len)
	{
		fprintf(stderr,"data Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	p = malloc(*data_len);
	memcpy(p,&element->data,*data_len);
	if(*p == 0)
	{
		data = NULL;
		free(p);
		p = NULL;
	}
	else
	{
		data = (u8 *)p;
	}
	counter += len;
	/*noack*/
	len = sizeof(element->len) + sizeof(int);
	if(p_size < counter + len)
    {
        fprintf(stderr,"noack Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(noack,&element->data,sizeof(int));

	return 0;
err:
	return -1;
}
