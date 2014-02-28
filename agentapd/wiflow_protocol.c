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
	element = (struct wiflow_pdu_element *)(pdu + counter);
    len = sizeof(element->len) + element->len;
    if(pdu_size < counter + len)
    {
        fprintf(stderr,"bssid Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    p = malloc(element->len);
    memcpy(p,&element->data,element->len);
    params->bssid = (u8 *)p;
    counter += len;
    /* ifname */
	element = (struct wiflow_pdu_element *)(pdu + counter);
    len = sizeof(element->len) + element->len;
    if(pdu_size < counter + len)
    {
        fprintf(stderr,"ifname Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    p = malloc(element->len);
    memcpy(p,&element->data,element->len);
    params->ifname = (const char *)p;
    counter += len;
    /* ssid */
	element = (struct wiflow_pdu_element *)(pdu + counter);
    len = sizeof(element->len) + element->len;
    if(pdu_size < counter + len)
    {
        fprintf(stderr,"ssid Error,%s:%d\n",__FILE__,__LINE__);
        goto err;  
    }
    p = malloc(element->len);
    memcpy(p,&element->data,element->len);
    params->ssid = (const u8 *)p;
    counter += len;
    /* ssid_len */
	element = (struct wiflow_pdu_element *)(pdu + counter);
    len = sizeof(element->len) + element->len;
    if(pdu_size < counter + len)
    {
        fprintf(stderr,"ssid_len Error,%s:%d\n",__FILE__,__LINE__);
        goto err;  
    }
    memcpy(&params->ssid_len,&element->data,element->len);
    counter += len;
    /* own_addr */
	element = (struct wiflow_pdu_element *)(pdu + counter);
    len = sizeof(element->len) + element->len;
    if(pdu_size < counter + len)
    {
        fprintf(stderr,"own_addr Error,%s:%d\n",__FILE__,__LINE__);
        goto err; 
    }
    params->own_addr = malloc(element->len);
    memcpy(params->own_addr,&element->data,element->len);

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


int wpa_init_capa_format(char * pdu, int *pdu_size,struct wpa_driver_capa *capa)
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
		len = sizeof(element->len) + INT_SIZE;
		if(pdu_size < counter + len)
		{
			goto err; 
		}
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = INT_SIZE;
		memcpy(&element->data,&capa->key_mgmt,element->len);
		counter += len;
		/* enc */
		len = sizeof(element->len) + INT_SIZE;
		if(pdu_size < counter + len)
		{
			goto err; 
		}
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = INT_SIZE;
		memcpy(&element->data,&capa->enc,element->len);
		counter += len;
		/* auth */
		len = sizeof(element->len) + INT_SIZE;
		if(pdu_size < counter + len)
		{
			goto err;  
		}
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = INT_SIZE;
		memcpy(&element->data,&capa->auth,element->len);
		counter += len;
		/* flags */
		len = sizeof(element->len) + INT_SIZE;
		if(pdu_size < counter + len)
		{
			goto err;  
		}
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = INT_SIZE;
		memcpy(&element->data,&capa->flags,element->len);
		counter += len;
		/* max_scan_ssids */
		len = sizeof(element->len) + INT_SIZE;
		if(pdu_size < counter + len)
		{
			goto err; 
		}
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = INT_SIZE;
		memcpy(&element->data,&capa->max_scan_ssids,element->len);
		counter += len;
		/* max_sched_scan_ssids */
		len = sizeof(element->len) + INT_SIZE;
		if(pdu_size < counter + len)
		{
			goto err;  
		}
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = INT_SIZE;
		memcpy(&element->data,&capa->max_sched_scan_ssids,element->len);
		counter += len;
		/* sched_scan_supported */
		len = sizeof(element->len) + INT_SIZE;
		if(pdu_size < counter + len)
		{
			goto err;  
		}
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = INT_SIZE;
		memcpy(&element->data,&capa->sched_scan_supported,element->len);
		counter += len;
		/* max_match_sets */
		len = sizeof(element->len) + INT_SIZE;
		if(pdu_size < counter + len)
		{
			goto err;  
		}
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = INT_SIZE;
		memcpy(&element->data,&capa->max_match_sets,element->len);
		counter += len;
		/* max_remain_on_chan */
		len = sizeof(element->len) + INT_SIZE;
		if(pdu_size < counter + len)
		{
			goto err;  
		}
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = INT_SIZE;
		memcpy(&element->data,&capa->max_remain_on_chan,element->len);
		counter += len;
		/* max_stations */
		len = sizeof(element->len) + INT_SIZE;
		if(pdu_size < counter + len)
		{
			goto err;  
		}
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = INT_SIZE;
		memcpy(&element->data,&capa->max_stations,element->len);
		counter += len;
		/* probe_resp_offloads */
		len = sizeof(element->len) + INT_SIZE;
		if(pdu_size < counter + len)
		{
			goto err;  
		}
		element = (struct wiflow_pdu_element *)(pdu + counter);
		element->len = INT_SIZE;
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
    if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu) || params == NULL)
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
	 
	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu) || capa == NULL)
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
}

int wpa_set_country_parser(char * pdu, int pdu_size, char *alpha2_arg)
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
	alpha2_arg = (char *)p;
	counter += len;

err:
    return -1;
}


int wpa_get_hw_feature_format(char * pdu, int *pdu_size, u16 *num_modes, u16 *flags)
{
	struct wiflow_pdu *wpdu;
	struct wiflow_pdu_element *element;
	int counter = 0;
	int len;
	int pdu_size = *p_size;
	 
	if(pdu == NULL || pdu_size < sizeof(struct wiflow_pdu) || num_modes == NULL || flags == NULL)
	{
		fprintf(stderr,"wpa_init_params_format args Error,%s:%d\n",__FILE__,__LINE__); 
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
	memcpy(&element->data,alpha2_arg,element->len);
	counter += len;
	/*flags*/
	element = (struct wiflow_pdu_element *)(pdu + counter);
	element->len = FLAGS;
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


