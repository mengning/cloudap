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
#include "utils/list.h"
#include "common/ieee802_11_defs.h"
#include "driver.h"
#include "wiflow_protocol.h"

#define MAX_SSID_LEN    32

int wiflow_pdu_format(char * pdu, int *p_size, enum wiflow_commands type)
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
	struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt*)data;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
    int pdu_size = *p_size;

	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu))
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
	len = sizeof(element->len) + sizeof(struct ieee80211_mgmt);
	if(p_size < counter + len)
	{
		 fprintf(stderr,"ieee80211_mgmt Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(mgmt,&element->data,sizeof(struct ieee80211_mgmt));
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
	if(addr == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,addr,element->len);
	}
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
	if(bridge_ifname == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,bridge_ifname,element->len);
	}
	counter += len;
	*p_size = counter;
	return 0;
err:
	return -1;
}

int wpa_i802_set_wds_sta_parser(char *pdu, int p_size,u8 **addr, int *aid, int *val,char **bridge_ifname)
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
		*addr = NULL;
		free(p);
		p = NULL;
	}
	else 
	{
		*addr = (u8 *)p;
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
		*bridge_ifname= NULL;
		free(p);
		p = NULL;
	}
	else 
	{
		*bridge_ifname = p;
	}
	
	return 0;
err:
	return -1;
}

int wpa_sta_add_format(char *pdu, int *p_size,struct hostapd_sta_add_params *params)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
	const struct ieee80211_ht_capabilities *ht_capab; 
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
	len = sizeof(element->len) + 32;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"supp_rates Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = 32;
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
    p = malloc(32);
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
    params->ht_capabilities=  (const struct ieee80211_ht_capabilities *)p;
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
	memcpy(&element->data,&type,element->len);
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
	if(addr == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,addr,element->len);
	}
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
	if(force_ifname == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,force_ifname,element->len);
	}
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
	if(if_addr == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,if_addr,element->len);
	}
	counter += len;

	*p_size = counter;
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
    func_params->force_ifname= p;
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

int wpa_set_freq_parser(char * pdu, int p_size, struct hostapd_freq_params * freq)
{
	struct wiflow_pdu *wpdu;
    	struct wiflow_pdu_element *element;
    	int counter = 0;
    	int len;

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
    memcpy(freq,&element->data,sizeof(struct hostapd_freq_params));
	return 0;
err:
	return -1;
}

int wpa_sta_set_flags_format(char * pdu,int * p_size,const u8 * addr,int total_flags,int flags_or,int flags_and)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
    int pdu_size = *p_size;
	int int_size = sizeof(int);

	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu))
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
	if(addr == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,addr,element->len);
	};
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

int wpa_sta_set_flags_parser(char *pdu, int p_size, u8 **addr, int* total_flags,
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
		*addr = NULL;
		free(p);
		p = NULL;
	}
	else 
	{
		*addr = (u8 *)p;
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

int wpa_set_rts_format(char * pdu, int *p_size, int rts)
{
    struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
	if(pdu == NULL || *p_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_set_rts_format args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,*p_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
    wpdu->type = WIFLOW_NL80211_SET_RTS_REQUEST;
    counter += sizeof(struct wiflow_pdu);
    /*rts*/
    len = sizeof(element->len) + sizeof(int);
    if(*p_size < counter + len)
    {
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    element->len = sizeof(int);
    memcpy(&element->data,&rts,sizeof(int));
    counter += len;
    *p_size = counter;
    return 0;
err:
    return -1;
}

int wpa_set_rts_parser(char * pdu, int p_size, int * rts)
{
    struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
	if(pdu == NULL || p_size < sizeof(struct wiflow_pdu) || rts == NULL)
    {
        fprintf(stderr,"wpa_set_rts_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,p_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
    if(wpdu->type != WIFLOW_NL80211_SET_RTS_REQUEST)
    {
        fprintf(stderr,"wpdu->type Error,%s:%d\n",__FILE__,__LINE__);
        goto err;   
    }
	counter += sizeof(struct wiflow_pdu);
	/*rts*/
	len = sizeof(element->len) + sizeof(int);
    if(p_size < counter + len)
    {
        fprintf(stderr,"rts Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    memcpy(rts,&element->data,sizeof(int));
	
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
	if(dst == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,dst,element->len);
	}
	counter += len;
	/*data*/
	len = sizeof(element->len) + data_len;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"data Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = data_len;
	if(data == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,data,element->len);
	}
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

int wpa_send_action_parser(char * pdu,int p_size,unsigned int *freq,unsigned int *wait_time,
									u8 ** dst,u8 ** data,size_t *data_len)
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
		*dst = (u8 *)p;
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
		*data= NULL;
		free(p);
		p = NULL;
	}
	else 
	{
		*data= (u8 *)p;
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

int wpa_set_tx_queue_params_format(char * pdu, int * p_size, int queue, int aifs, int cw_min, 
											int cw_max, int burst_time)
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

int wpa_set_tx_queue_params_parser(char * pdu,int p_size,struct wpa_set_tx_queue_params * tx_params)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
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

int wpa_scan2_format(char * pdu, int * p_size, struct wpa_driver_scan_params *params, int data_len)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
    int pdu_size = *p_size;

	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu) || params == NULL)
    {
        fprintf(stderr,"wpa_scan2_format args Error,%s:%d\n",__FILE__,__LINE__); 
        goto err;   
    }
	wpdu = (struct wiflow_pdu*)pdu;
	wpdu->type = WIFLOW_NL80211_SCAN2_REQUEST;
	counter += sizeof(struct wiflow_pdu);
	/*params*/
	len = sizeof(element->len) + data_len;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"params Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = data_len;
	memcpy(&element->data, params->freqs,element->len);
	counter += len;

	*p_size = counter;
	return 0;
err:
	return -1;
}

int wpa_scan2_parser(char * pdu,int p_size,struct wpa_driver_scan_params * params)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
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

int wpa_sta_deauth_parser(char * pdu,int p_size, u8 ** addr,int *reason)
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
		*addr = NULL;
		free(p);
		p = NULL;
	}
	else 
	{
		*addr = (u8 *)p;
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

int wpa_sta_deauth_format(char * pdu,int * p_size,const u8 * addr,int reason)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
    int pdu_size = *p_size;

	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_sta_deauth_format args Error,%s:%d\n",__FILE__,__LINE__); 
        goto err;   
    }
	wpdu = (struct wiflow_pdu*)pdu;
	wpdu->type = WIFLOW_NL80211_STA_DEAUTH_REQUEST;
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
	if(addr == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,addr,element->len);
	}
	counter += len;
	/*reason*/
	len = sizeof(element->len) + sizeof(int);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"reason Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(int);
	memcpy(&element->data,&reason,element->len);
	counter += len;

	*p_size = counter;
	return 0;
err:
	return -1;
}

int wpa_sta_disassoc_format(char * pdu,int * p_size,const u8 * addr,int reason)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
    int pdu_size = *p_size;

	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_sta_disassoc_format args Error,%s:%d\n",__FILE__,__LINE__); 
        goto err;   
    }
	wpdu = (struct wiflow_pdu*)pdu;
	wpdu->type = WIFLOW_NL80211_STA_DISASSOC_REQUEST;
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
	if(addr == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,addr,element->len);
	}
	counter += len;
	/*reason*/
	len = sizeof(element->len) + sizeof(int);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"reason Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(int);
	memcpy(&element->data,&reason,element->len);
	counter += len;

	*p_size = counter;
	return 0;
err:
	return -1;
}

int wpa_sta_disassoc_parser(char * pdu,int p_size, u8 ** addr,int *reason)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
	char *p;

	if(pdu == NULL || p_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_sta_disassoc_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,p_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
	if(wpdu->type != WIFLOW_NL80211_STA_DISASSOC_REQUEST)
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
		*addr = NULL;
		free(p);
		p = NULL;
	}
	else 
	{
		*addr = (u8 *)p;
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

int wpa_set_key_format(char * pdu,int * p_size,enum wpa_alg alg,const u8 * addr,int key_idx,
				int set_tx,const u8 * seq,size_t seq_len,const u8 * key,size_t key_len)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
    int pdu_size = *p_size;
	int int_size = sizeof(int);

	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_set_key_format args Error,%s:%d\n",__FILE__,__LINE__); 
        goto err;   
    }
	wpdu = (struct wiflow_pdu*)pdu;
	wpdu->type = WIFLOW_NL80211_SET_KEY_REQUEST;
	counter += sizeof(struct wiflow_pdu);

	/*alg*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"alg Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = int_size;
	memcpy(&element->data,&alg,element->len);
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
	if(addr == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,addr,element->len);
	}
	counter += len;
	/*key_idx*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"key_idx Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = int_size;
	memcpy(&element->data,&key_idx,element->len);
	counter += len;
	/*set_tx*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"set_tx Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = int_size;
	memcpy(&element->data,&set_tx,element->len);
	counter += len;
	/*seq_len*/
	len = sizeof(element->len) + sizeof(seq_len);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"seq_len Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(seq_len);
	memcpy(&element->data,&seq_len,element->len);
	counter += len;
	/*seq*/
	len = sizeof(element->len) + seq_len;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"seq Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = seq_len;
	if(seq == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,seq,element->len);
	}
	counter += len;
	/*key_len*/
	len = sizeof(element->len) + sizeof(key_len);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"key_len Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(seq_len);
	memcpy(&element->data,&key_len,element->len);
	counter += len;
	/*key*/
	len = sizeof(element->len) + key_len;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"key Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = key_len;
	if(key == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,key,element->len);
	}
	counter += len;

	*p_size = counter;
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

int wpa_send_mlme_format(char * pdu,int * p_size,const u8 * data, size_t data_len, int noack)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
    int pdu_size = *p_size;

	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_send_mlme_format args Error,%s:%d\n",__FILE__,__LINE__); 
        goto err;   
    }
	wpdu = (struct wiflow_pdu*)pdu;
	wpdu->type = WIFLOW_NL80211_SEND_MLME_REQUEST;
	counter += sizeof(struct wiflow_pdu);
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
	/*data*/
	len = sizeof(element->len) + data_len;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"data Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = data_len;
	if(data== NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,data,element->len);
	}
	counter += len;
	/*noack*/
	len = sizeof(element->len) + sizeof(int);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"noack Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(int);
	memcpy(&element->data,&noack,element->len);
	counter += len;
	*p_size = counter;
	return 0;
err:
	return -1;
}

int wpa_send_mlme_parser(char * pdu,int p_size, u8 ** data, size_t * data_len,int * noack)
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
		*data = NULL;
		free(p);
		p = NULL;
	}
	else
	{
		*data = (u8 *)p;
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

int wpa_get_seqnum_format(char *pdu, int *p_size, const u8 *addr, int idx, u8 *seq)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
	int seq_len;
    int pdu_size = *p_size;

	
	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_get_seqnum_format args Error,%s:%d\n",__FILE__,__LINE__); 
        goto err;   
    }
	wpdu = (struct wiflow_pdu*)pdu;
	wpdu->type = WIFLOW_NL80211_GET_SEQNUM_REQUEST;
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
	if(addr == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,addr,element->len);
	}
	counter += len;
	/*idx*/
	len = sizeof(element->len) + sizeof(int);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"idx Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(int);
	memcpy(&element->data,&idx,element->len);
	counter += len;
	/*seq_len*/
	seq_len = strlen((char*)seq);
	len = sizeof(element->len) + sizeof(int);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"seq_len Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(int);
	memcpy(&element->data,&seq_len,element->len);
	counter += len;
	/*seq*/
	len = sizeof(element->len) + seq_len;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"seq Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = seq_len;
	if(seq == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,&seq,element->len);
	}
	counter += len;
	
	*p_size = counter;
	return 0;
err:
	return -1;
}

int wpa_get_seqnum_parser(char * pdu,int p_size, u8 ** addr, int *idx, u8 * seq)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
	int seq_len;
	char *p;

	if(pdu == NULL || p_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_get_seqnum_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,p_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
	if(wpdu->type != WIFLOW_NL80211_GET_SEQNUM_REQUEST)
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
	memcpy(p,&element->data, ETH_ALEN);
	if(*p == 0)
	{
		*addr = NULL;
		free(p);
		p = NULL;
	}
	else
	{
		*addr = (u8 *)p;
	}
	counter += len;
	/*idx*/
	len = sizeof(element->len) + sizeof(idx);
	if(p_size < counter + len)
	{
		fprintf(stderr,"idx Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(idx,&element->data,sizeof(idx));
	counter += len;
	/*seq_len*/
	len = sizeof(element->len) + sizeof(seq_len);
	if(p_size < counter + len)
	{
		fprintf(stderr,"seq_len Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&seq_len,&element->data,sizeof(seq_len));
	counter += len;
	/*seq*/
	len = sizeof(element->len) + seq_len;
	if(p_size < counter + len)
	{
		fprintf(stderr,"seq Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	p = malloc(seq_len);
	memcpy(p,&element->data, seq_len);
	if(*p == 0)
	{
		seq = NULL;
		free(p);
		p = NULL;
	}
	else
	{
		seq = (u8 *)p;
	}
	return 0;
err:
	return -1;
}

int wpa_set_sta_vlan_format(char * pdu,int * p_size,const u8 * addr,int vlan_id)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
    int pdu_size = *p_size;

	
	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_set_sta_vlan_format args Error,%s:%d\n",__FILE__,__LINE__); 
        goto err;   
    }
	wpdu = (struct wiflow_pdu*)pdu;
	wpdu->type = WIFLOW_NL80211_SET_STA_VLAN_REQUEST;
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
	if(addr == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,addr,element->len);
	}
	counter += len;
	/*vlan_id*/
	len = sizeof(element->len) + sizeof(int);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"vlan_id Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(int);
	memcpy(&element->data,&vlan_id,element->len);
	counter += len;

	*p_size = counter;
	return 0;
err: 
	return -1;
}

int wpa_set_sta_vlan_parser(char * pdu,int p_size, u8 ** addr,int *vlan_id)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
	char *p;

	if(pdu == NULL || p_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_set_sta_vlan_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,p_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
	if(wpdu->type != WIFLOW_NL80211_SET_STA_VLAN_REQUEST)
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
	memcpy(p,&element->data, ETH_ALEN);
	if(*p == 0)
	{
		*addr = NULL;
		free(p);
		p = NULL;
	}
	else
	{
		*addr = (u8 *)p;
	}
	counter += len;
	/*vlan_id*/
	len = sizeof(element->len) + sizeof(vlan_id);
	if(p_size < counter + len)
	{
		fprintf(stderr,"vlan_id Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(vlan_id,&element->data,sizeof(vlan_id));

	return 0;
err:
	return -1;
}

int wpa_hapd_send_eapol_format(char * pdu,int * p_size,const u8 * addr,const u8 * data,size_t data_len,int encrypt,u32 flags)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
    int pdu_size = *p_size;

	
	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_set_sta_vlan_format args Error,%s:%d\n",__FILE__,__LINE__); 
        goto err;   
    }
	wpdu = (struct wiflow_pdu*)pdu;
	wpdu->type = WIFLOW_NL80211_HAPD_SEND_EAPOL_REQUEST;
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
	if(addr == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,addr,element->len);
	}
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
	/*data*/
	len = sizeof(element->len) + data_len;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"data Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = data_len;
	if(data == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,data,element->len);
	}
	counter += len;
	/*encrypt*/
	len = sizeof(element->len) + sizeof(encrypt);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"encrypt Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(int);
	memcpy(&element->data,&encrypt,element->len);
	counter += len;
	/*flags*/
	len = sizeof(element->len) + sizeof(flags);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"flags Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(flags);
	memcpy(&element->data,&flags,element->len);
	counter += len;
	
	*p_size = counter;
	return 0;
err:
	return -1;
}

int wpa_hapd_send_eapol_parser(char * pdu,int p_size, u8 ** addr, u8 ** data,size_t *data_len,int *encrypt,u32 *flags)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
	char *p;

	if(pdu == NULL || p_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_set_sta_vlan_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,p_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
	if(wpdu->type != WIFLOW_NL80211_HAPD_SEND_EAPOL_REQUEST)
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
	memcpy(p,&element->data, ETH_ALEN);
	if(*p == 0)
	{
		*addr = NULL;
		free(p);
		p = NULL;
	}
	else
	{
		*addr = (u8 *)p;
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
	memcpy(p,&element->data, *data_len);
	if(*p == 0)
	{
		*data = NULL;
		free(p);
		p = NULL;
	}
	else
	{
		*data = (u8 *)p;
	}
	counter += len;
	/*encrypt*/
	len = sizeof(element->len) + sizeof(encrypt);
	if(p_size < counter + len)
	{
		fprintf(stderr,"encrypt Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(encrypt,&element->data,sizeof(encrypt));
	counter += len;
	/*flags*/
	len = sizeof(element->len) + sizeof(flags);
	if(p_size < counter + len)
	{
		fprintf(stderr,"flags Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(flags,&element->data,sizeof(flags));
	return 0;
err:
	return -1;
}

int wpa_read_sta_data_format(char *pdu, int *p_size, struct hostap_sta_driver_data *data, const u8 *addr)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
    int pdu_size = *p_size;

	
	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu) || data == NULL)
    {
        fprintf(stderr,"wpa_read_sta_data_format args Error,%s:%d\n",__FILE__,__LINE__); 
        goto err;   
    }
	wpdu = (struct wiflow_pdu*)pdu;
	wpdu->type = WIFLOW_NL80211_READ_STA_DATA_REQUEST;
	counter += sizeof(struct wiflow_pdu);
	/*data*/
	len = sizeof(element->len) + sizeof(struct hostap_sta_driver_data);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"data Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(struct hostap_sta_driver_data);
	if(data == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,data,element->len);
	}
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
	if(addr == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,addr,element->len);
	}
	counter += len;

	*p_size = counter;
	return 0;
err:
	return -1;
}

int wpa_read_sta_data_parser(char * pdu,int p_size,struct hostap_sta_driver_data * data, u8 ** addr)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
	struct hostap_sta_driver_data *p;
	char *q;

	if(pdu == NULL || p_size < sizeof(struct wiflow_pdu) || data == NULL)
    {
        fprintf(stderr,"wpa_read_sta_data_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,p_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
	if(wpdu->type != WIFLOW_NL80211_READ_STA_DATA_REQUEST)
	{
		fprintf(stderr,"wpdu->type Error,%s:%d\n",__FILE__,__LINE__);
        goto err;	
	}
	counter += sizeof(struct wiflow_pdu);
	/*data*/
	len = sizeof(element->len) + sizeof(struct hostap_sta_driver_data);
	if(p_size < counter + len)
	{
		fprintf(stderr,"data Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	p = (struct hostap_sta_driver_data *)malloc(sizeof(struct hostap_sta_driver_data));
	memcpy(p,&element->data, sizeof(struct hostap_sta_driver_data));
	if(p == NULL)
	{
		data = NULL;
		free(p);
		p = NULL;
	}
	else
	{
		data = p;
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
	q = malloc(ETH_ALEN);
	memcpy(q,&element->data, ETH_ALEN);
	if(*q == 0)
	{
		*addr = NULL;
		free(q);
		q = NULL;
	}
	else
	{
		*addr = (u8 *)q;
	}
	return 0;
err:
	return -1;
}

int wpa_poll_client_format(char * pdu, int * p_size, const u8 * addr, int qos)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
    int pdu_size = *p_size;

	
	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_poll_client_parser args Error,%s:%d\n",__FILE__,__LINE__); 
        goto err;   
    }
	wpdu = (struct wiflow_pdu*)pdu;
	wpdu->type = WIFLOW_NL80211_POLL_CLIENT_REQUEST;
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
	if(addr == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,addr,element->len);
	}
	counter += len;
	/*qos*/
	len = sizeof(element->len) + sizeof(int);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"qos Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(int);
	memcpy(&element->data,&qos,element->len);
	counter += len;

	*p_size = counter;
	return 0;
err: 
	return -1;
}

int wpa_poll_client_parser(char * pdu,int p_size, u8 ** addr,int * qos)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
	char *p;

	if(pdu == NULL || p_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_poll_client_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,p_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
	if(wpdu->type != WIFLOW_NL80211_POLL_CLIENT_REQUEST)
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
	memcpy(p,&element->data, ETH_ALEN);
	if(*p == 0)
	{
		*addr = NULL;
		free(p);
		p = NULL;
	}
	else
	{
		*addr = (u8 *)p;
	}
	counter += len;
	/*qos*/
	len = sizeof(element->len) + sizeof(qos);
	if(p_size < counter + len)
	{
		fprintf(stderr,"qos Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(qos,&element->data,sizeof(qos));

	return 0;
err:
	return -1;
}

int wpa_get_inact_sec_format(char * pdu,int *p_size, const u8 * addr)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
    int pdu_size = *p_size;

	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_poll_client_parser args Error,%s:%d\n",__FILE__,__LINE__); 
        goto err;   
    }
	wpdu = (struct wiflow_pdu*)pdu;
	wpdu->type = WIFLOW_NL80211_GET_INACT_SEC_REQUEST;
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
	if(addr == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,addr,element->len);
	}
	counter += len;
	*p_size = counter;
	return 0;
err:
	return -1;
}

int wpa_get_inact_sec_parser(char * pdu,int p_size, u8 ** addr)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
	char *p;

	if(pdu == NULL || p_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_poll_client_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,p_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
	if(wpdu->type != WIFLOW_NL80211_GET_INACT_SEC_REQUEST)
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
	memcpy(p,&element->data, ETH_ALEN);
	if(*p == 0)
	{
		*addr = NULL;
		free(p);
		p = NULL;
	}
	else
	{
		*addr = (u8 *)p;
	}
	return 0;
err:
	return -1;
}


int wpa_sta_remove_format(char * pdu,int *p_size, const u8 * addr)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
    int pdu_size = *p_size;

	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_sta_remove_format args Error,%s:%d\n",__FILE__,__LINE__); 
        goto err;   
    }
	wpdu = (struct wiflow_pdu*)pdu;
	wpdu->type = WIFLOW_NL80211_STA_REMOVE_REQUEST;
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
	if(addr == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,addr,element->len);
	}
	counter += len;
	*p_size = counter;
	return 0;
err:
	return -1;
}

int wpa_sta_remove_parser(char * pdu,int p_size, u8 ** addr)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
	char *p;

	if(pdu == NULL || p_size < sizeof(struct wiflow_pdu))
    {
        fprintf(stderr,"wpa_sta_remove_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,p_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
	if(wpdu->type != WIFLOW_NL80211_STA_REMOVE_REQUEST)
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
	memcpy(p,&element->data, ETH_ALEN);
	if(*p == 0)
	{
		*addr = NULL;
		free(p);
		p = NULL;
	}
	else
	{
		*addr = (u8 *)p;
	}
	return 0;
err:
	return -1;
}

int wpa_set_ap_format(char * pdu,int * p_size,struct wpa_driver_ap_params * params)
{  
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
    int pdu_size = *p_size;

	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu) || params == NULL)
    {
        fprintf(stderr,"wpa_set_ap_format args Error,%s:%d\n",__FILE__,__LINE__); 
        goto err;   
    }
	wpdu = (struct wiflow_pdu*)pdu;
	wpdu->type = WIFLOW_NL80211_SET_AP_REQUEST;
	counter += sizeof(struct wiflow_pdu);
	/*head_len*/
	len = sizeof(element->len) + sizeof(params->head_len);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"head_len Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->head_len);
	memcpy(&element->data,&params->head_len,element->len);
	counter += len;
	/*head*/
	len = sizeof(element->len) + params->head_len;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"head Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = params->head_len;
	if(params->head == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,params->head,element->len);
	}
	counter += len;
	/*tail_len*/
	len = sizeof(element->len) + sizeof(params->tail_len);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"tail_len Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->tail_len);
	memcpy(&element->data,&params->tail_len,element->len);
	counter += len;
	/*tail*/
	len = sizeof(element->len) + params->tail_len;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"tail Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = params->tail_len;
	if(params->head == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,params->tail,element->len);
	}
	counter += len;
	/*dtim_period*/
	len = sizeof(element->len) + sizeof(params->dtim_period);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"dtim_period Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->dtim_period);
	memcpy(&element->data,&params->dtim_period,element->len);
	counter += len;
	/*beacon_int*/
	len = sizeof(element->len) + sizeof(params->beacon_int);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"beacon_int Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->beacon_int);
	memcpy(&element->data,&params->beacon_int,element->len);
	counter += len;
	/*basic_rates*/
	len = sizeof(element->len) + sizeof(int);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"basic_rates Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(int);
	if(params->basic_rates == NULL)
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,params->basic_rates,element->len);
	}
	counter += len;
	/*proberesp_len*/
	len = sizeof(element->len) + sizeof(params->proberesp_len);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"proberesp_len Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->proberesp_len);
	memcpy(&element->data,&params->proberesp_len,element->len);
	counter += len;
	/*proberesp*/
	len = sizeof(element->len) + params->proberesp_len;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"proberesp Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = params->proberesp_len;
	if(params->proberesp == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,params->proberesp,element->len);
	}
	counter += len;
	/*hide_ssid*/
	len = sizeof(element->len) + sizeof(int);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"hide_ssid Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(int);
	memcpy(&element->data,&params->hide_ssid,element->len);
	counter += len;
	/*pairwise_ciphers*/
	len = sizeof(element->len) + sizeof(params->pairwise_ciphers);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"pairwise_ciphers Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->pairwise_ciphers);
	memcpy(&element->data,&params->pairwise_ciphers,element->len);
	counter += len;
	/*group_cipher*/
	len = sizeof(element->len) + sizeof(params->group_cipher);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"group_cipher Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->group_cipher);
	memcpy(&element->data,&params->group_cipher,element->len);
	counter += len;
	/*key_mgmt_suites*/
	len = sizeof(element->len) + sizeof(params->key_mgmt_suites);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"key_mgmt_suites Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->key_mgmt_suites);
	memcpy(&element->data,&params->key_mgmt_suites,element->len);
	counter += len;
	/*auth_algs*/
	len = sizeof(element->len) + sizeof(params->auth_algs);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"auth_algs Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->auth_algs);
	memcpy(&element->data,&params->auth_algs,element->len);
	counter += len;
	/*wpa_version*/
	len = sizeof(element->len) + sizeof(params->wpa_version);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"wpa_version Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->wpa_version);
	memcpy(&element->data,&params->wpa_version,element->len);
	counter += len;
	/*privacy*/
	len = sizeof(element->len) + sizeof(params->privacy);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"privacy Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->privacy);
	memcpy(&element->data,&params->privacy,element->len);
	counter += len;
	/*isolate*/
	len = sizeof(element->len) + sizeof(params->isolate);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"isolate Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->isolate);
	memcpy(&element->data,&params->isolate,element->len);
	counter += len;
	/*cts_protect*/
	len = sizeof(element->len) + sizeof(params->cts_protect);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"cts_protect Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->cts_protect);
	memcpy(&element->data,&params->cts_protect,element->len);
	counter += len;
	/*preamble*/
	len = sizeof(element->len) + sizeof(params->preamble);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"preamble Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->preamble);
	memcpy(&element->data,&params->preamble,element->len);
	counter += len;
	/*short_slot_time*/
	len = sizeof(element->len) + sizeof(params->short_slot_time);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"short_slot_time Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->short_slot_time);
	memcpy(&element->data,&params->short_slot_time,element->len);
	counter += len;
	/*ht_opmode*/
	len = sizeof(element->len) + sizeof(params->ht_opmode);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"ht_opmode Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->ht_opmode);
	memcpy(&element->data,&params->ht_opmode,element->len);
	counter += len;
	/*interworking*/
	len = sizeof(element->len) + sizeof(params->interworking);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"interworking Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->interworking);
	memcpy(&element->data,&params->interworking,element->len);
	counter += len;
	/*hessid*/
	len = sizeof(element->len) + ETH_ALEN;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"addr Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = ETH_ALEN;
	if(params->hessid == NULL) 
	{
		memset(&element->data,0,element->len);
	}
	else 
	{
		memcpy(&element->data,params->hessid,element->len);
	}
	counter += len;
	/*access_network_type*/
	len = sizeof(element->len) + sizeof(params->access_network_type);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"access_network_type Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->access_network_type);
	memcpy(&element->data,&params->access_network_type,element->len);
	counter += len;
	/*ap_max_inactivity*/
	len = sizeof(element->len) + sizeof(params->ap_max_inactivity);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"ap_max_inactivity Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->ap_max_inactivity);
	memcpy(&element->data,&params->ap_max_inactivity,element->len);
	counter += len;
	/*disable_dgaf*/
	len = sizeof(element->len) + sizeof(params->disable_dgaf);
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"disable_dgaf Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(params->disable_dgaf);
	memcpy(&element->data,&params->disable_dgaf,element->len);
	counter += len;

	*p_size = counter;
	return 0;
err:
	return -1;
}

int wpa_set_ap_parser(char * pdu,int pdu_size, struct wpa_driver_ap_params * params)
{
	struct wiflow_pdu *wpdu;
    struct wiflow_pdu_element *element;
    int counter = 0;
    int len;
	int t_size = sizeof(size_t);
	int int_size = sizeof(int);
	char *p;

	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu) || params == NULL)
    {
        fprintf(stderr,"wpa_set_ap_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,pdu_size);
        goto err;   
    }
    wpdu = (struct wiflow_pdu*)pdu;
	if(wpdu->type != WIFLOW_NL80211_SET_AP_REQUEST)
	{
		fprintf(stderr,"wpdu->type Error,%s:%d\n",__FILE__,__LINE__);
        goto err;	
	}
	counter += sizeof(struct wiflow_pdu);
	/*head_len*/
	len = sizeof(element->len) + t_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"head_len Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&params->head_len,&element->data,t_size);
	counter += len;
	/*head*/
	len = sizeof(element->len) + params->head_len;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"head Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	p = malloc(params->head_len);
	memcpy(p,&element->data, params->head_len);
	if(*p == 0)
	{
		params->head = NULL;
		free(p);
		p = NULL;
	}
	else
	{
		params->head= (u8 *)p;
	}
	counter += len;
	/*tail_len*/
	len = sizeof(element->len) + t_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"tail_len Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&params->tail_len,&element->data,sizeof(t_size));
	counter += len;
	/*tail*/
	len = sizeof(element->len) + params->tail_len;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"tail Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	p = malloc(params->tail_len);
	memcpy(p,&element->data, params->tail_len);
	if(*p == 0)
	{
		params->tail = NULL;
		free(p);
		p = NULL;
	}
	else
	{
		params->tail= (u8 *)p;
	}
	counter += len;
	/*dtim_period*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"dtim_period Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&params->dtim_period,&element->data,int_size);
	counter += len;
	/*beacon_int*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"beacon_int Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&params->beacon_int,&element->data,int_size);
	counter += len;
	/*basic_rates*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"basic_rates Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(params->basic_rates,&element->data,int_size);
	counter += len;
	/*proberesp_len*/
	len = sizeof(element->len) + t_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"proberesp_len Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&params->proberesp_len,&element->data,t_size);
	counter += len;
	/*proberesp*/
	len = sizeof(element->len) + params->proberesp_len;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"proberesp Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	p = malloc(params->proberesp_len);
	memcpy(p,&element->data, params->proberesp_len);
	if(*p == 0)
	{
		params->proberesp= NULL;
		free(p);
		p = NULL;
	}
	else
	{
		params->proberesp= (u8 *)p;
	}
	counter += len;
	/*hide_ssid*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"hide_ssid Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&params->hide_ssid,&element->data,int_size);
	counter += len;
	/*pairwise_ciphers*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"pairwise_ciphers Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&params->pairwise_ciphers,&element->data,int_size);
	counter += len;
	/*group_cipher*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"group_cipher Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&params->group_cipher,&element->data,int_size);
	counter += len;
	/*key_mgmt_suites*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"key_mgmt_suites Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&params->key_mgmt_suites,&element->data,int_size);
	counter += len;
	/*auth_algs*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"auth_algs Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&params->auth_algs,&element->data,int_size);
	counter += len;
	/*wpa_version*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"wpa_version Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&params->wpa_version,&element->data,int_size);
	counter += len;
	/*privacy*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"privacy Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&params->privacy,&element->data,int_size);
	counter += len;
	/*isolate*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"isolate Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&params->isolate,&element->data,int_size);
	counter += len;
	/*cts_protect*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"cts_protect Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&params->cts_protect,&element->data,int_size);
	counter += len;
	/*preamble*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"preamble Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&params->preamble,&element->data,int_size);
	counter += len;
	/*short_slot_time*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"short_slot_time Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&params->short_slot_time,&element->data,int_size);
	counter += len;
	/*ht_opmode*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"ht_opmode Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&params->ht_opmode,&element->data,int_size);
	counter += len;
	/*interworking*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"interworking Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&params->interworking,&element->data,int_size);
	counter += len;
	/*hessid*/
	len = sizeof(element->len) + ETH_ALEN;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"hessid Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	p = malloc(ETH_ALEN);
	memcpy(p,&element->data, ETH_ALEN);
	if(*p == 0)
	{
		params->hessid = NULL;
		free(p);
		p = NULL;
	}
	else
	{
		params->hessid = (u8 *)p;
	}
	counter += len;
	/*access_network_type*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"access_network_type Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&params->access_network_type,&element->data,int_size);
	counter += len;
	/*ap_max_inactivity*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"ap_max_inactivity Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&params->ap_max_inactivity,&element->data,int_size);
	counter += len;
	/*disable_dgaf*/
	len = sizeof(element->len) + int_size;
	if(pdu_size < counter + len)
	{
		fprintf(stderr,"disable_dgaf Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	element = (struct wiflow_pdu_element *)(pdu + counter);
	memcpy(&params->disable_dgaf,&element->data,int_size);
	counter += len;
	
	return 0;
err:
	return -1;
}

int wpa_set_frag_format(char * pdu, int *p_size,int frag)
{
	struct wiflow_pdu *wpdu;
	struct wiflow_pdu_element *element;
	int counter = 0;
	int len;
	int pdu_size = *p_size;
	
	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu))
	{
		fprintf(stderr,"wpa_init_params_format args Error,%s:%d\n",__FILE__,__LINE__); 
		goto err;	
	}	
	wpdu = (struct wiflow_pdu*)pdu;
	wpdu->type = WIFLOW_NL80211_SET_FRAG;
	counter += sizeof(struct wiflow_pdu);
	element = (struct wiflow_pdu_element *)(pdu + counter);
	
	element->len = 4;

	len = sizeof(element->len) + element->len;
	if(pdu_size < counter + len)
	{
		goto err; 
	}
	memcpy(&element->data,&frag,element->len);
	counter += len;	
	*p_size = counter;
	return 0;

err:
	return -1;	
}


int wpa_set_frag_parser(char * pdu, int pdu_size)
 {
	struct wiflow_pdu *wpdu;
	struct wiflow_pdu_element *element;
	int counter = 0;
	int frag = -1;
	int len;
	char *p;
    if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu))
     {
        fprintf(stderr,"wpa_set_frag_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,pdu_size);
		goto err;   
     }
     wpdu = (struct wiflow_pdu*)pdu;
     if(wpdu->type != WIFLOW_NL80211_SET_FRAG)
     {
		fprintf(stderr,"wpdu->type Error,%s:%d\n",__FILE__,__LINE__);
		goto err;   
    }
	counter += sizeof(struct wiflow_pdu);
 	element = (struct wiflow_pdu_element *)(pdu + counter);
	len = sizeof(element->len) + element->len;
 	if(pdu_size < counter + len)
 	{
		goto err; 
 	}
	p = malloc(element->len);
	memcpy(p,&element->data,element->len);
	frag = atoi(p);
 	counter += len;
	return frag;
	
 err:
     return -1;
 }

int wpa_if_remove_format(char * pdu, int *p_size,enum wpa_driver_if_type type,
					 const char *ifname)
{
	struct wiflow_pdu *wpdu;
	struct wiflow_pdu_element *element;
	int pdu_size = *p_size;
	int counter = 0;
	int len;

	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu))
	{
		fprintf(stderr,"wpa_if_remove args Error,%s:%d\n",__FILE__,__LINE__); 
			goto err;	
	}	
	wpdu = (struct wiflow_pdu*)pdu;
	wpdu->type = WIFLOW_NL80211_IF_REMOVE;
	counter += sizeof(struct wiflow_pdu);
	/* type */
    len = sizeof(element->len) + 4;
    if(pdu_size < counter + len)
    {
        goto err;  
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    element->len = 4;
    memcpy(&element->data,&type,element->len);
    counter += len;
	/* ifname */
    len = sizeof(element->len) + IFNAMSIZ + 1;
    if(pdu_size < counter + len)
    {
         goto err; 
    }
    element = (struct wiflow_pdu_element *)(pdu + counter);
    element->len = IFNAMSIZ + 1;
    memcpy(&element->data,&ifname,element->len);
    counter += len;
	return 0;
	
err:
	return -1;		
 
}

 int wpa_if_remove_parser(char * pdu, int pdu_size,struct wpa_function_params *func_params)
 {
 	struct wiflow_pdu *wpdu;
	struct wiflow_pdu_element *element;
	int counter = 0;
	int len;
	enum wpa_driver_if_type type;
	char *p;
    if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu))
     {
        fprintf(stderr,"wpa_if_remove_parserr args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,pdu_size);
		goto err;   
     }
     wpdu = (struct wiflow_pdu*)pdu;
     if(wpdu->type != WIFLOW_NL80211_IF_REMOVE)
     {
		fprintf(stderr,"wpdu->type Error,%s:%d\n",__FILE__,__LINE__);
		goto err;   
     }
	 wpdu = (struct wiflow_pdu*)pdu;
	 wpdu->type = WIFLOW_INIT_PARAMS_RESPONSE;
	 counter += sizeof(struct wiflow_pdu);
	 /* type */
	 len = sizeof(element->len) + 4;
	 if(pdu_size < counter + len)
	 {
		 goto err; 
	 }
	 element = (struct wiflow_pdu_element *)(pdu + counter);
	 element->len = 4;
	 p = malloc(element->len);
	 memcpy(p,&element->data,element->len);
	 type = atoi(p);
 	 counter += len;
	 /* ifname */
	len = sizeof(element->len) + IFNAMSIZ + 1;
	if(pdu_size < counter + len)
	 {
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
	 return type;
 err:
     return -1;
 }

 
 int i802_flush_format(char *pdu, int *p_size)
 {
	 struct wiflow_pdu *wpdu;
	 int pdu_size = *p_size;
 
	 if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu) )
	 {
		 fprintf(stderr,"i802_flush_format args Error,%s:%d\n",__FILE__,__LINE__); 
		  goto err;   
	 }
	 wpdu = (struct wiflow_pdu*)pdu;
	 wpdu->type = WIFLOW_NL80211_i802_FLUSH_REQUEST;
	 
	 return 0;
 err:
	 return -1;
 }
 
 int i802_flush_parser(char *pdu, int p_size)
 {
	 return 0;
 }


 
 int wpa_init_capa_format(char * pdu, int *p_size,struct wpa_driver_capa *capa)
 {
		 struct wiflow_pdu *wpdu;
		 struct wiflow_pdu_element *element;
		 int counter = 0;
		 int len;
		 int pdu_size = *p_size;
		  
		 if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu) || capa == NULL)
		 {
			 fprintf(stderr,"wpa_init_params_format args Error,%s:%d\n",__FILE__,__LINE__); 
			 goto err;	 
		 }
	 
		 wpdu = (struct wiflow_pdu*)pdu;
		 wpdu->type = WIFLOW_INIT_CAPA_RESPONSE;
		 counter += sizeof(struct wiflow_pdu);
		 /* key_mgmt */
 // 	 len = sizeof(element->len) + INT_SIZE;
		 len = sizeof(element->len) + 4;
		 if(pdu_size < counter + len)
		 {
			 goto err; 
		 }
		 element = (struct wiflow_pdu_element *)(pdu + counter);
 // 	 element->len = INT_SIZE;
		 element->len = 4;
		 memcpy(&element->data,&capa->key_mgmt,element->len);
		 counter += len;
		 /* enc */
 // 	 len = sizeof(element->len) + INT_SIZE;
		 len = sizeof(element->len) + 4;
		 if(pdu_size < counter + len)
		 {
			 goto err; 
		 }
		 element = (struct wiflow_pdu_element *)(pdu + counter);
 // 	 element->len = INT_SIZE;
		 element->len = 4;
		 memcpy(&element->data,&capa->enc,element->len);
		 counter += len;
		 /* auth */
 // 	 len = sizeof(element->len) + INT_SIZE;
		 len = sizeof(element->len) + 4;
		 if(pdu_size < counter + len)
		 {
			 goto err;	
		 }
		 element = (struct wiflow_pdu_element *)(pdu + counter);
 // 	 element->len = INT_SIZE;
		 element->len = 4;
		 memcpy(&element->data,&capa->auth,element->len);
		 counter += len;
		 /* flags */
 // 	 len = sizeof(element->len) + INT_SIZE;
		 len = sizeof(element->len) + 4;
		 if(pdu_size < counter + len)
		 {
			 goto err;	
		 }
		 element = (struct wiflow_pdu_element *)(pdu + counter);
 // 	 element->len = INT_SIZE;
		 element->len = 4;
		 memcpy(&element->data,&capa->flags,element->len);
		 counter += len;
		 /* max_scan_ssids */
 // 	 len = sizeof(element->len) + INT_SIZE;
		 len = sizeof(element->len) + 4;
		 if(pdu_size < counter + len)
		 {
			 goto err; 
		 }
		 element = (struct wiflow_pdu_element *)(pdu + counter);
 // 	 element->len = INT_SIZE;
		 element->len = 4;
		 memcpy(&element->data,&capa->max_scan_ssids,element->len);
		 counter += len;
		 /* max_sched_scan_ssids */
 // 	 len = sizeof(element->len) + INT_SIZE;
		 len = sizeof(element->len) + 4;
		 if(pdu_size < counter + len)
		 {
			 goto err;	
		 }
		 element = (struct wiflow_pdu_element *)(pdu + counter);
 // 	 element->len = INT_SIZE;
		 element->len = 4;
		 memcpy(&element->data,&capa->max_sched_scan_ssids,element->len);
		 counter += len;
		 /* sched_scan_supported */
 // 	 len = sizeof(element->len) + INT_SIZE;
		 len = sizeof(element->len) + 4;
		 if(pdu_size < counter + len)
		 {
			 goto err;	
		 }
		 element = (struct wiflow_pdu_element *)(pdu + counter);
 // 	 element->len = INT_SIZE;
		 element->len = 4;
		 memcpy(&element->data,&capa->sched_scan_supported,element->len);
		 counter += len;
		 /* max_match_sets */
 // 	 len = sizeof(element->len) + INT_SIZE;
		 len = sizeof(element->len) + 4;
		 if(pdu_size < counter + len)
		 {
			 goto err;	
		 }
		 element = (struct wiflow_pdu_element *)(pdu + counter);
 // 	 element->len = INT_SIZE;
		 element->len = 4;
		 memcpy(&element->data,&capa->max_match_sets,element->len);
		 counter += len;
		 /* max_remain_on_chan */
 // 	 len = sizeof(element->len) + INT_SIZE;
		 len = sizeof(element->len) + 4;
		 if(pdu_size < counter + len)
		 {
			 goto err;	
		 }
		 element = (struct wiflow_pdu_element *)(pdu + counter);
 // 	 element->len = INT_SIZE;
		 element->len = 4;
		 memcpy(&element->data,&capa->max_remain_on_chan,element->len);
		 counter += len;
		 /* max_stations */
 // 	 len = sizeof(element->len) + INT_SIZE;
		 len = sizeof(element->len) + 4;
		 if(pdu_size < counter + len)
		 {
			 goto err;	
		 }
		 element = (struct wiflow_pdu_element *)(pdu + counter);
 // 	 element->len = INT_SIZE;
		 element->len = 4;
		 memcpy(&element->data,&capa->max_stations,element->len);
		 counter += len;
		 /* probe_resp_offloads */
 // 	 len = sizeof(element->len) + INT_SIZE;
		 len = sizeof(element->len) + 4;
		 if(pdu_size < counter + len)
		 {
			 goto err;	
		 }
		 element = (struct wiflow_pdu_element *)(pdu + counter);
 // 	 element->len = INT_SIZE;
		 element->len = 4;
		 memcpy(&element->data,&capa->probe_resp_offloads,element->len);
		 counter += len;
	 
		 *p_size = counter;
		 return 0; 
	 err:
		 return -1;
 }
 
 
 int wpa_init_capa_parser(char * pdu, int pdu_size,struct wpa_driver_capa *capa)
 {
	 struct wiflow_pdu *wpdu;
	 struct wiflow_pdu_element *element;
	 int counter = 0;
	 int len;
	 char * p;
	 if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu) || capa == NULL)
	 {
		 fprintf(stderr,"wpa_init_params_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,pdu_size);
		 goto err;	 
	 }
	 wpdu = (struct wiflow_pdu*)pdu;
	 if(wpdu->type != WIFLOW_INIT_CAPA_RESPONSE)
	 {
		 fprintf(stderr,"wpdu->type Error,%s:%d\n",__FILE__,__LINE__);
		 goto err;	 
	 }
	 counter += sizeof(struct wiflow_pdu);
	 /* key_mgmt */
	 element = (struct wiflow_pdu_element *)(pdu + counter);
	 len = sizeof(element->len) + element->len;
	 if(pdu_size < counter + len)
	 {
		 goto err; 
	 }
	 p = malloc(element->len);
	 memcpy(p,&element->data,element->len);
	 capa->key_mgmt = (int)*p;
	 free(p);
	 counter += len;
	 /* enc */
	 element = (struct wiflow_pdu_element *)(pdu + counter);
	 len = sizeof(element->len) + element->len;
	 if(pdu_size < counter + len)
	 {
		 goto err; 
	 }
	 p = malloc(element->len);
	 memcpy(p,&element->data,element->len);
	 capa->enc = (int)*p;
	 free(p);
	 counter += len;
	 /* auth */
	 element = (struct wiflow_pdu_element *)(pdu + counter);
	 len = sizeof(element->len) + element->len;
	 if(pdu_size < counter + len)
	 {
		 goto err;	
	 }
	 p = malloc(element->len);
	 memcpy(p,&element->data,element->len);
	 capa->auth = (int)*p;
	 free(p);
	 counter += len;
	 /* flags */
	 element = (struct wiflow_pdu_element *)(pdu + counter);
	 len = sizeof(element->len) + element->len;
	 if(pdu_size < counter + len)
	 {
		 goto err;	
	 }
	 p = malloc(element->len);
	 memcpy(p,&element->data,element->len);
	 capa->flags = (int)*p;
	 free(p);
	 counter += len;
	 /* max_scan_ssids */
	 element = (struct wiflow_pdu_element *)(pdu + counter);
	 len = sizeof(element->len) + element->len;
	 if(pdu_size < counter + len)
	 {
		 goto err; 
	 }
	 p = malloc(element->len);
	 memcpy(p,&element->data,element->len);
	 capa->max_scan_ssids = (int)*p;
	 free(p);
	 counter += len;
	 /* max_sched_scan_ssids */
	 element = (struct wiflow_pdu_element *)(pdu + counter);
	 len = sizeof(element->len) + element->len;
	 if(pdu_size < counter + len)
	 {
		 goto err;	
	 }
	 p = malloc(element->len);
	 memcpy(p,&element->data,element->len);
	 capa->max_sched_scan_ssids = (int)*p;
	 free(p);
	 counter += len;
	 /* sched_scan_supported */
	 element = (struct wiflow_pdu_element *)(pdu + counter);
	 len = sizeof(element->len) + element->len;
	 if(pdu_size < counter + len)
	 {
		 goto err;	
	 }
	 p = malloc(element->len);
	 memcpy(p,&element->data,element->len);
	 capa->sched_scan_supported = (int)*p;
	 free(p);
	 counter += len;
	 /* max_match_sets */
	 element = (struct wiflow_pdu_element *)(pdu + counter);
	 len = sizeof(element->len) + element->len;
	 if(pdu_size < counter + len)
	 {
		 goto err;	
	 }
	 p = malloc(element->len);
	 memcpy(p,&element->data,element->len);
	 capa->max_match_sets = (int)*p;
	 free(p);
	 counter += len;
	 /* max_remain_on_chan */
	 element = (struct wiflow_pdu_element *)(pdu + counter);
	 len = sizeof(element->len) + element->len;
	 if(pdu_size < counter + len)
	 {
		 goto err;	
	 }
	 p = malloc(element->len);
	 memcpy(p,&element->data,element->len);
	 capa->max_remain_on_chan = (int)*p;
	 free(p);
	 counter += len;
	 /* max_stations */
	 element = (struct wiflow_pdu_element *)(pdu + counter);
	 len = sizeof(element->len) + element->len;
	 if(pdu_size < counter + len)
	 {
		 goto err;	
	 }
	 p = malloc(element->len);
	 memcpy(p,&element->data,element->len);
	 capa->max_stations = (int)*p;
	 free(p);
	 counter += len;
	 /* probe_resp_offloads */
	 element = (struct wiflow_pdu_element *)(pdu + counter);
	 len = sizeof(element->len) + element->len;
	 if(pdu_size < counter + len)
	 {
		 goto err;	
	 }
	 p = malloc(element->len);
	 memcpy(p,&element->data,element->len);
	 capa->probe_resp_offloads = (int)*p;
	 free(p);
 
	 return 0;
 err:
	 return -1;
 }
 
 
 int local_default_capa(struct wpa_driver_capa *capa)
 {
	 if(capa == NULL)
		 return -1;
	 
	 capa->auth = 1;
	 capa->enc = 1;
	 capa->flags = 1;
	 capa->key_mgmt = 1;
	 capa->max_match_sets = 1;
	 capa->max_remain_on_chan = 1;
	 capa->max_scan_ssids = 1;
	 capa->max_stations = 1;
	 capa->max_sched_scan_ssids = 1;
	 capa->probe_resp_offloads = 1;
	 capa->sched_scan_supported = 1;
 
	 return 0;
 }
 
 
 int wpa_set_country_format(char * pdu, int *p_size,const char *alpha2_arg)
 {
	 struct wiflow_pdu *wpdu;
	 struct wiflow_pdu_element *element;
	 int counter = 0;
	 int len;
	 int pdu_size = *p_size;
	  
	 if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu) || alpha2_arg == NULL)
	 {
		 fprintf(stderr,"wpa_init_params_format args Error,%s:%d\n",__FILE__,__LINE__); 
		 goto err;	 
	 }
	 
	 wpdu = (struct wiflow_pdu*)pdu;
	 wpdu->type = WIFLOW_SET_COUNTRY;
	 counter += sizeof(struct wiflow_pdu);
	 element = (struct wiflow_pdu_element *)(pdu + counter);
	 element->len = COUNTRY_SIZE;
	 len = sizeof(element->len) + element->len;
	 if(pdu_size < counter + len)
	 {
		 goto err; 
	 }
	 memcpy(&element->data,alpha2_arg,element->len);
	 counter += len;
	 
	 *p_size = counter;
	 return 0;
 
 err:
	 return -1;
 }
 
 int wpa_set_country_parser(char * pdu, int pdu_size, char **alpha2_arg)
 {
	 struct wiflow_pdu *wpdu;
	 struct wiflow_pdu_element *element;
	 int counter = 0;
	 int len;
	 char * p;
	 if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu) || alpha2_arg == NULL)
	 {
		 fprintf(stderr,"wpa_init_params_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,pdu_size);
		 goto err;	 
	 }
	 wpdu = (struct wiflow_pdu*)pdu;
	 if(wpdu->type != WIFLOW_SET_COUNTRY)
	 {
		 fprintf(stderr,"wpdu->type Error,%s:%d\n",__FILE__,__LINE__);
		 goto err;	 
	 }
	 counter += sizeof(struct wiflow_pdu);
	 /* alpha2_arg*/
	 element = (struct wiflow_pdu_element *)(pdu + counter);
	 len = sizeof(element->len) + element->len;
	 if(pdu_size < counter + len)
	 {
		 goto err; 
	 }
	 p = malloc(element->len);
	 memcpy(p,&element->data,element->len);
	 *alpha2_arg = (char *)p;
	 counter += len;
 
 err:
	 return -1;
 }
 
 
 int wpa_get_hw_feature_format(char * pdu, int *p_size, u16 *num_modes, u16 *flags)
 {
	 struct wiflow_pdu *wpdu;
	 struct wiflow_pdu_element *element;
	 int counter = 0;
	 int len;
	 int pdu_size = *p_size;
	  
	 if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu))
	 {
		 fprintf(stderr,"wpa_get_hw_feature_format args Error,%s:%d\n",__FILE__,__LINE__); 
		 goto err;	 
	 }
	 
	 wpdu = (struct wiflow_pdu*)pdu;
	 wpdu->type = WPA_GET_HW_MODE_REQUEST;
	 counter += sizeof(struct wiflow_pdu);
	 /*num_modes*/
	 element = (struct wiflow_pdu_element *)(pdu + counter);
	 element->len = NUM_MODES;
	 len = sizeof(element->len) + element->len;
	 if(pdu_size < counter + len)
	 {
		 goto err; 
	 }
	 memset(&element->data, 0, element->len);
	 counter += len;
	 /*flags*/
	 element = (struct wiflow_pdu_element *)(pdu + counter);
	 element->len = FLAGS;
	 len = sizeof(element->len) + element->len;
	 if(pdu_size < counter + len)
	 {
		 goto err; 
	 }
	 memset(&element->data,0,element->len);
	 counter += len;
 
	 *p_size = counter;
	 return 0;
 
 err:
	 return -1;
 }
 
 int wpa_get_hw_feature_parser(char * pdu, int pdu_size, u16 *num_modes, u16 *flags)
 {
	 wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	 struct wiflow_pdu *wpdu;
	 struct wiflow_pdu_element *element;
	 int counter = 0;
	 int len;
	
	 if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu))
	 {
		 fprintf(stderr,"wpa_init_params_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,pdu_size);
		 goto err;	 
	 }
	 wpdu = (struct wiflow_pdu*)pdu;
	 if(wpdu->type != WPA_GET_HW_MODE_REQUEST)
	 {
		 fprintf(stderr,"wpdu->type Error,%s:%d\n",__FILE__,__LINE__);
		 goto err;	 
	 }
	 counter += sizeof(struct wiflow_pdu);
	 /* num_modes*/
	 element = (struct wiflow_pdu_element *)(pdu + counter);
	 len = sizeof(element->len) + NUM_MODES;
	 if(pdu_size < counter + len)
	 {
		 goto err; 
	 }
	 memcpy(num_modes, &element->data, NUM_MODES);
	 counter += len;
	 /* flags*/
	 len = sizeof(element->len) + FLAGS;
	 element = (struct wiflow_pdu_element *)(pdu + counter);
	 if(pdu_size < counter + len)
	 {
		 fprintf(stderr,"flags Error,%s:%d\n",__FILE__,__LINE__);
		 goto err; 
	 }
	 memcpy(flags, &element->data, FLAGS);
	 wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
 	 return 0;
 err:
	 return -1;
 }



struct hostapd_hw_modes * local_default_hw_mode()
{
	wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	struct hostapd_hw_modes *local_hw_mode;
	local_hw_mode = (struct hostapd_hw_modes *)malloc(200);
	if(local_hw_mode == NULL)
	{
		fprintf(stderr,"local_default_hw_mode args Error,%s:%d\n",__FILE__,__LINE__);
		goto err;
	}
	u8 mcs_set[16] = {255,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0};
	u8 vht_mcs_set[8] = {0};
	int basic_rate[4] = {10, 20, 55, 110};
	struct hostapd_channel_data *channel;
	int *rate;
	rate = malloc(sizeof(basic_rate));
	memcpy(rate,basic_rate,sizeof(basic_rate));
	local_hw_mode = (struct hostapd_hw_modes *)malloc(sizeof(struct hostapd_hw_modes));
	channel = (struct hostapd_channel_data *)malloc(sizeof(struct hostapd_channel_data));
	/*set default hw modes*/
	channel->chan = 1;
	channel->flag = 80;
	channel->freq = 2412;
	channel->max_tx_power = 20;
	local_hw_mode->a_mpdu_params = 27;
	local_hw_mode->flags = 80;
	local_hw_mode->ht_capab = 4462;
	memcpy(local_hw_mode->mcs_set, mcs_set, 16);
	local_hw_mode->num_channels = 14;
	local_hw_mode->mode = 1;
	local_hw_mode->num_rates = 12;
	local_hw_mode->vht_capab = 0;
	local_hw_mode->rates = rate;
	memcpy(local_hw_mode->vht_mcs_set, vht_mcs_set, 8);
	local_hw_mode->channels = channel;
	return local_hw_mode;

err:
	return NULL;
}
 
 
 
 int remote_hw_modes_format(char * pdu, int *p_size, struct hostapd_hw_modes *remote_hw_modes)
 {
		wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
		 struct wiflow_pdu *wpdu;
		 struct wiflow_pdu_element *element;
		 int counter = 0;
		 int len;
		 int pdu_size = *p_size;
		  
		 if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu) || remote_hw_modes == NULL)
		 {
			 fprintf(stderr,"wpa_init_params_format args Error,%s:%d\n",__FILE__,__LINE__); 
			 goto err;	 
		 }
		 
		 wpdu = (struct wiflow_pdu*)pdu;
		 wpdu->type = REMOTE_HW_MODE;
		 counter += sizeof(struct wiflow_pdu);
		 /*modes*/
		 element = (struct wiflow_pdu_element *)(pdu + counter);
		 element->len = 4;
		 len = sizeof(element->len) + element->len;
		 if(pdu_size < counter + len)
		 {
			 goto err; 
		 }
		 memcpy(&element->data,&remote_hw_modes->mode,element->len);
		 counter += len;
		 /*num_channels*/
		 element = (struct wiflow_pdu_element *)(pdu + counter);
		 element->len = 4;
		 len = sizeof(element->len) + element->len;
		 if(pdu_size < counter + len)
		 {
			 goto err; 
		 }
		 memcpy(&element->data,&remote_hw_modes->num_channels,element->len);
		 counter += len;
		 /*channels*/
		 element = (struct wiflow_pdu_element *)(pdu + counter);
		 element->len = remote_hw_modes->num_channels * sizeof(struct hostapd_channel_data);
		 len = sizeof(element->len) + element->len;
		 if(pdu_size < counter + len)
		 {
			 goto err; 
		 }
		 memcpy(&element->data,remote_hw_modes->channels,element->len);
		 counter += len;
		 /*num_rates*/
		 element = (struct wiflow_pdu_element *)(pdu + counter);
		 element->len = 4;
		 len = sizeof(element->len) + element->len;
		 if(pdu_size < counter + len)
		 {
			 goto err; 
		 }
		 memcpy(&element->data,&remote_hw_modes->num_rates,element->len);
		 counter += len;
		 /*rates*/
		 element = (struct wiflow_pdu_element *)(pdu + counter);
		 element->len = RATES;
		 len = sizeof(element->len) + element->len;
		 if(pdu_size < counter + len)
		 {
			 goto err; 
		 }
		 memcpy(&element->data,remote_hw_modes->rates,element->len);
		 counter += len;
		 /*others*/
		 element = (struct wiflow_pdu_element *)(pdu + counter);
		 element->len = sizeof(u16) + sizeof(remote_hw_modes->mcs_set) + sizeof(u8)
		 					+ sizeof(u32) + sizeof(remote_hw_modes->vht_mcs_set);
		 len = sizeof(element->len) + element->len;
		 if(pdu_size < counter + len)
		 {
			 goto err; 
		 }
		 memcpy(&element->data,&remote_hw_modes->ht_capab,element->len);
		 counter += len;
 
		 *p_size = counter;
		 return 0;
	 
	 err:
		 return -1;
 
 }
 
 
 int remote_hw_modes_parser(char * pdu, int pdu_size, struct hostapd_hw_modes *remote_hw_modes)
 {
	 wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	 struct wiflow_pdu *wpdu;
	 struct wiflow_pdu_element *element;
	 int counter = 0;
	 int len;
	 char* p;

	 if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu) || remote_hw_modes == NULL)
	 {
		 fprintf(stderr,"remote_hw_modes_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,pdu_size);
		 goto err;	 
	 }
	 wpdu = (struct wiflow_pdu*)pdu;
	 if(wpdu->type != REMOTE_HW_MODE)
	 {
		 fprintf(stderr,"wpdu->type Error,%s:%d\n",__FILE__,__LINE__);
		 goto err;	 
	 }
	 counter += sizeof(struct wiflow_pdu);
	 /* mode*/
	 element = (struct wiflow_pdu_element *)(pdu + counter);
	 len = sizeof(element->len) + element->len;
	 if(pdu_size < counter + len)
	 {
		 goto err; 
	 }
	 memcpy(&remote_hw_modes->mode,&element->data,element->len);
	 counter += len;
	 /* num_channels*/
	 element = (struct wiflow_pdu_element *)(pdu + counter);
	 len = sizeof(element->len) + element->len;
	 if(pdu_size < counter + len)
	 {
		 goto err; 
	 }
	 memcpy(&remote_hw_modes->num_channels,&element->data,element->len);
	 counter += len;
	 /* channels*/
	 element = (struct wiflow_pdu_element *)(pdu + counter);
	 len = sizeof(element->len) + element->len;
	 if(pdu_size < counter + len)
	 {
		 goto err; 
	 }
	 p = malloc(element->len);
	 memcpy(p,&element->data,element->len);
	 remote_hw_modes->channels = (struct hostapd_channel_data *)p;
	 counter += len;
	 /* others*/
	 element = (struct wiflow_pdu_element *)(pdu + counter);
	 len = sizeof(element->len) + element->len;
	 if(pdu_size < counter + len)
	 {
		 goto err; 
	 }
	 memcpy(&remote_hw_modes->ht_capab,&element->data,element->len);
	 
 	 return 0;
 err:
	 return -1;
 }

int wpa_supplicant_data_format(char *pdu, int *p_size, union wpa_event_data *data, enum wpa_event_type *event)
{
	struct wiflow_pdu *wpdu;
	struct wiflow_pdu_element *element;
	int counter = 0;
	int len;
	int pdu_size = *p_size;
	 
	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu))
	{
		fprintf(stderr,"wpa_init_params_format args Error,%s:%d\n",__FILE__,__LINE__); 
		goto err;	 
	}
	 
	wpdu = (struct wiflow_pdu*)pdu;
	wpdu->type = WPA_SUP_EVENT;
	counter += sizeof(struct wiflow_pdu);
	/*event*/
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(enum wpa_event_type);
	len = sizeof(element->len) + element->len;
	if(pdu_size < counter + len)
	{
		 goto err; 
	}
	memcpy(&element->data, event, element->len);
	counter += len;
	/*wpa_event_data*/
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = sizeof(union wpa_event_data);
	len = sizeof(element->len) + element->len;
	if(pdu_size < counter + len)
	{
		 goto err; 
	}
	memcpy(&element->data, data, element->len);
	counter += len;

	switch(*event)
	{
	case EVENT_MICHAEL_MIC_FAILURE:
		/*src*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = ETH_ALEN;
		len = sizeof(element->len) + element->len;
		if(pdu_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, data->michael_mic_failure.src, element->len);
		counter += len;
		break;
	case EVENT_TX_STATUS:
		/*dst*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = ETH_ALEN;
		len = sizeof(element->len) + element->len;
		if(pdu_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, data->tx_status.dst, element->len);
		counter += len;
		/*data*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = data->tx_status.data_len;
		len = sizeof(element->len) + element->len;
		if(pdu_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, data->tx_status.data, element->len);
		counter += len;
		break;
	case EVENT_EAPOL_TX_STATUS:
		/*dst*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = ETH_ALEN;
		len = sizeof(element->len) + element->len;
		if(pdu_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, data->eapol_tx_status.dst, element->len);
		counter += len;
		/*data*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = data->eapol_tx_status.data_len;
		len = sizeof(element->len) + element->len;
		if(pdu_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, data->eapol_tx_status.data, element->len);
		counter += len;
		break;
	case EVENT_RX_FROM_UNKNOWN:
		/*bssid*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = ETH_ALEN;
		len = sizeof(element->len) + element->len;
		if(pdu_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, data->rx_from_unknown.bssid, element->len);
		counter += len;
		/*addr*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = ETH_ALEN;
		len = sizeof(element->len) + element->len;
		if(pdu_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, data->rx_from_unknown.addr, element->len);
		counter += len;
		break;
	case EVENT_RX_MGMT:
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = data->rx_mgmt.frame_len;
		len = sizeof(element->len) + element->len;
		if(pdu_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, data->rx_mgmt.frame, element->len);
		counter += len;
		break;
	case EVENT_ASSOC:
		/*req_ies*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = data->assoc_info.req_ies_len;
		len = sizeof(element->len) + element->len;
		if(pdu_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, data->assoc_info.req_ies, element->len);
		counter += len;
		/*resp_ies*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = data->assoc_info.resp_ies_len;
		len = sizeof(element->len) + element->len;
		if(pdu_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, data->assoc_info.resp_ies, element->len);
		counter += len;
		/*beacon_ies*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = data->assoc_info.beacon_ies_len;
		len = sizeof(element->len) + element->len;
		if(pdu_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, data->assoc_info.beacon_ies, element->len);
		counter += len;
		/*addr*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = ETH_ALEN;
		len = sizeof(element->len) + element->len;
		if(pdu_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, data->assoc_info.addr, element->len);
		counter += len;
		break;
	case EVENT_DEAUTH:
		/*addr*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = ETH_ALEN;
		len = sizeof(element->len) + element->len;
		if(pdu_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, data->assoc_info.addr, element->len);
		counter += len;
		/*ie*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = data->deauth_info.ie_len;
		len = sizeof(element->len) + element->len;
		if(pdu_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, data->deauth_info.ie, element->len);
		counter += len;
		break;
	case EVENT_RX_ACTION:
		/*da*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = ETH_ALEN;
		len = sizeof(element->len) + element->len;
		if(pdu_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, data->rx_action.da, element->len);
		counter += len;
		/*sa*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = ETH_ALEN;
		len = sizeof(element->len) + element->len;
		if(pdu_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, data->rx_action.sa, element->len);
		counter += len;
		/*bssid*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = ETH_ALEN;
		len = sizeof(element->len) + element->len;
		if(pdu_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, data->rx_action.bssid, element->len);
		counter += len;
		/*data*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = data->rx_action.len;
		len = sizeof(element->len) + element->len;
		if(pdu_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, data->rx_action.data, element->len);
		counter += len;
		break;
	case EVENT_AUTH:
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = data->auth.ies_len;
		len = sizeof(element->len) + element->len;
		if(pdu_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, data->auth.ies, element->len);
		counter += len;
		break;
		
	default:
		break;
		}
	
	*p_size = counter;
	return 0;

err:
	 return -1;
}




int wpa_supplicant_data_parser(char *pdu, int p_size, union wpa_event_data *data, enum wpa_event_type *event)
{
	wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	 struct wiflow_pdu *wpdu;
	 struct wiflow_pdu_element *element;
	 int counter = 0;
	 int len;
	 char* p;

	 if(pdu == NULL || p_size < sizeof(struct wiflow_pdu))
	 {
		 fprintf(stderr,"wpa_init_params_parser args Error,%s:%d,pdu_size:%d\n",__FILE__,__LINE__,p_size);
		 goto err;	 
	 }
	 wpdu = (struct wiflow_pdu*)pdu;
	 if(wpdu->type != WPA_SUP_EVENT)
	 {
		 fprintf(stderr,"wpdu->type Error,%s:%d\n",__FILE__,__LINE__);
		 goto err;	 
	 }
	 counter += sizeof(struct wiflow_pdu);
	 /* event_type*/
	 element = (struct wiflow_pdu_element *)(pdu + counter);
	 len = sizeof(element->len) + element->len;
	 if(p_size < counter + len)
	 {
		 goto err; 
	 }
	 memcpy(event, &element->data, element->len);
	 counter += len;
	 /* event_data*/
	 element = (struct wiflow_pdu_element *)(pdu + counter);
	 len = sizeof(element->len) + element->len;
	 if(p_size < counter + len)
	 {
		 goto err; 
	 }
	 memcpy(data, &element->data, element->len);
	 counter += len;

	 switch(*event)
	 {
	 case EVENT_MICHAEL_MIC_FAILURE:
	 	/*src*/
	 	element = (struct wiflow_pdu_element *)(pdu + counter);
		len = sizeof(element->len) + element->len;
		if(p_size < counter + len)
		{
		 	goto err; 
	 	}
	 	p = malloc(element->len);
		memcpy(p, &element->data, element->len);
		data->michael_mic_failure.src = (const u8*)p;
		counter += len;
		break;
	 case EVENT_TX_STATUS:
	 	/*dst*/
	 	element = (struct wiflow_pdu_element *)(pdu + counter);
		len = sizeof(element->len) + element->len;
		if(p_size < counter + len)
		{
		 	goto err; 
	 	}
	 	p = malloc(element->len);
		memcpy(p, &element->data, element->len);
		data->tx_status.dst = (const u8*)p;
		counter += len;
		/*data*/
	 	element = (struct wiflow_pdu_element *)(pdu + counter);
		len = sizeof(element->len) + element->len;
		if(p_size < counter + len)
		{
		 	goto err; 
	 	}
	 	p = malloc(element->len);
		memcpy(p, &element->data, element->len);
		data->tx_status.data = (const u8*)p;
		counter += len;
		break;
	case EVENT_EAPOL_TX_STATUS:
		/*dst*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		len = sizeof(element->len) + element->len;
		if(p_size < counter + len)
		{
		 	goto err; 
	 	}
	 	p = malloc(element->len);
		memcpy(p, &element->data, element->len);
		data->eapol_tx_status.dst = p;
		counter += len;
		/*dst*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		len = sizeof(element->len) + element->len;
		if(p_size < counter + len)
		{
		 	goto err; 
	 	}
	 	p = malloc(element->len);
		memcpy(p, &element->data, element->len);
		data->eapol_tx_status.data = (const u8*)p;
		counter += len;
		break;
	case EVENT_RX_FROM_UNKNOWN:
		/*bssid*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		len = sizeof(element->len) + element->len;
		if(p_size < counter + len)
		{
			goto err;
		}
		p = malloc(element->len);
		memcpy(p, &element->data, element->len);
		data->rx_from_unknown.bssid = (const u8*)p;
		counter += len;
		/*addr*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		len = sizeof(element->len) + element->len;
		if(p_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, &element->data, element->len);
		data->rx_from_unknown.addr = (const u8*)p;
		counter += len;
		break;
	case EVENT_RX_MGMT:
		element = (struct wiflow_pdu_element *)(pdu + counter);
		len = sizeof(element->len) + element->len;
		if(p_size < counter + len)
		{
			goto err;
		}
		p = malloc(element->len);
		memcpy(p, &element->data, element->len);
		data->rx_mgmt.frame = (const u8*)p;
		counter += len;
		break;
	case EVENT_ASSOC:
		/*req_ies*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		len = sizeof(element->len) + element->len;
		if(p_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, &element->data, element->len);
		data->assoc_info.req_ies = (const u8*)p;
		counter += len;
		/*resp_ies*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		len = sizeof(element->len) + element->len;
		if(p_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, &element->data, element->len);
		data->assoc_info.resp_ies = (const u8*)p;
		counter += len;
		/*beacon_ies*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		len = sizeof(element->len) + element->len;
		if(p_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, &element->data, element->len);
		data->assoc_info.beacon_ies = (const u8*)p;
		counter += len;
		/*addr*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		len = sizeof(element->len) + element->len;
		if(p_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, &element->data, element->len);
		data->assoc_info.addr = (const u8*)p;
		counter += len;
		break;
	case EVENT_DEAUTH:
		/*addr*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		len = sizeof(element->len) + element->len;
		if(p_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, &element->data, element->len);
		data->assoc_info.addr = p;
		counter += len;
		/*ie*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		len = sizeof(element->len) + element->len;
		if(p_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, &element->data, element->len);
		data->deauth_info.ie = (const u8*)p;
		counter += len;
		break;
	case EVENT_RX_ACTION:
		/*da*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		len = sizeof(element->len) + element->len;
		if(p_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, &element->data, element->len);
		data->rx_action.da = (const u8*)p;
		counter += len;
		/*sa*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		len = sizeof(element->len) + element->len;
		if(p_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, &element->data, element->len);
		data->rx_action.sa = (const u8*)p;
		counter += len;
		/*bssid*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		len = sizeof(element->len) + element->len;
		if(p_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, &element->data, element->len);
		data->rx_action.bssid = (const u8*)p;
		counter += len;
		/*data*/
		element = (struct wiflow_pdu_element *)(pdu + counter);
		len = sizeof(element->len) + element->len;
		if(p_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, &element->data, element->len);
		data->rx_action.data = (const u8*)p;
		counter += len;
		break;
	case EVENT_AUTH:
		element = (struct wiflow_pdu_element *)(pdu + counter);
		len = sizeof(element->len) + element->len;
		if(p_size < counter + len)
		{
			goto err;
		}
		memcpy(&element->data, &element->data, element->len);
		data->auth.ies = (const u8*)p;
		counter += len;
		break;
	default:
		break;
	 }

	 return 0;

err:
	 return -1;
			
}
