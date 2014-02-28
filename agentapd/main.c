/*
 * Agentapd interaction with socket to remoteapd(driver_nl80211ext)
 * Copyright (c) 2013-2014, SSE@USTCSZ mengning <mengning@ustc.edu.cn>
 *
 * agentapd(socket client)with Linux nl80211/cfg80211 - driver_nl80211ext.c(socket server)
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include<stdio.h> 			/* perror */
#include<stdlib.h>			/* exit	*/
#include<sys/types.h>		/* WNOHANG */
#include<sys/wait.h>		/* waitpid */
#include<string.h>			/* memset */

#include<arpa/inet.h> /* internet socket */
#include<assert.h>

#define PORT    5001
#define IP_ADDR "127.0.0.1"
#define MAX_CONNECT_QUEUE   1024

#include "driver.h"
#include "wiflow_protocol.h"

struct hostapd_data
{
    struct i802_bss * bss;
};

extern struct wpa_driver_ops *wpa_drivers[];
void * global_priv;
struct hostapd_data hapd;

void handle_agent_read(int sock, void *eloop_ctx, void *sock_ctx);
/*
 * 模仿hostapd调用driver
 * 注意call-down和driver call-up
 * call-down至少包括nl80211_global_init/nl80211_global_deinit,i802_init/i802_deinit
 * call-up至少包括wpa_supplicant_event,wpa_scan_results_free
 */

int main() 
{
    int i = 0;
    struct wpa_init_params params;
	if (eloop_init()) 
	{
		wpa_printf(MSG_ERROR, "Failed to initialize event loop");
		return -1;
	}
    /* init socket client */
    int sockfd = -1;
    char buf[MAX_BUF_LEN];
    int buf_size = 0;
    struct sockaddr_in serveraddr;
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(PORT);
    serveraddr.sin_addr.s_addr = inet_addr(IP_ADDR);
    //bzero(&(serveraddr.sin_zero), 8);/* in string.h */
    memset(&serveraddr.sin_zero, 0, 8);
    sockfd = socket(PF_INET,SOCK_STREAM,0);
    assert((sockfd != -1));
    int ret = connect(sockfd,(struct sockaddr *)&serveraddr,sizeof(struct sockaddr));
    if(ret == -1)
    {
        fprintf(stderr,"Connect Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    } 
	if (eloop_register_read_sock(sockfd, handle_agent_read, hapd.bss, NULL)) 
    {
		printf("Could not register agent read socket\n");
		return -1;
	}

    /* global init nl80211 */ 
	for (i = 0; wpa_drivers[i]; i++) 
	{
		if (wpa_drivers[i]->global_init) 
		{
			global_priv = wpa_drivers[i]->global_init();
			if (global_priv == NULL) {
				printf("global_init Failed to initialize\n");
				return -1;
			}
		}
	    
	}
	/* agent request AP params */
	buf_size = MAX_BUF_LEN;
	ret = wiflow_pdu_format(buf,&buf_size,WIFLOW_INIT_PARAMS_REQUEST);
    if(ret < 0 || buf_size <= 0)
    {
        fprintf(stderr,"wiflow_pdu_format Error,%s:%d\n",__FILE__,__LINE__);  
    }
    ret = send(sockfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"send Error,%s:%d\n",__FILE__,__LINE__);  
    }

	printf("NL80211 global initialized\n");
	eloop_run();
    return 0;
}

void wpa_supplicant_event(void *ctx, enum wpa_event_type event,
			  union wpa_event_data *data)
{
    printf("wpa_supplicant_event\n");
    return;
}

void wpa_scan_results_free(struct wpa_scan_results *res)
{
    return;   
}

void handle_agent_read(int sock, void *eloop_ctx, void *sock_ctx)
{
    int i = 0;
	int data_len = 0, encrypt = 0;
    char buf[MAX_BUF_LEN];
    struct wpa_init_params params;
	struct ieee80211_mgmt mgmt;
    struct i802_bss * bss = (struct i802_bss *)eloop_ctx;
    /* read nl80211 commands from remote  */
	int buf_size = 0;
	int ret;
    ret = recv(sock,buf,MAX_BUF_LEN,0);
    if(ret < 0)
    {
        fprintf(stderr,"Recv Error,%s:%d\n",__FILE__,__LINE__); 
    }
    struct wiflow_pdu *pdu = (struct wiflow_pdu*) buf;
 	switch (pdu->type) 
 	{
	case WIFLOW_INIT_PARAMS_RESPONSE:
        /* parse buf to params */
        ret = wpa_init_params_parser(buf,MAX_BUF_LEN,&params);
        if(ret < 0)
        {
            fprintf(stderr,"wpa_init_params_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
        params.global_priv = global_priv; 
        params.bssid = NULL; /* Not use remote bssid */
        params.test_socket = NULL;
        params.use_pae_group_addr = 0;
        params.num_bridge = 1;
        params.bridge = os_calloc(params.num_bridge, sizeof(char *));
    	if (params.bridge == NULL)
    	{
    	    fprintf(stderr,"os_calloc Error,%s:%d\n",__FILE__,__LINE__);
    		return ;
    	}	        
        wpa_hexdump(MSG_DEBUG, "nl80211ext: params->bssid",params.bssid, ETH_ALEN);
        wpa_printf(MSG_DEBUG, "nl80211ext: params->ifname:%s",params.ifname);
        wpa_printf(MSG_DEBUG, "nl80211ext: params->ssid:%s",params.ssid);
        wpa_printf(MSG_DEBUG, "nl80211ext: params->ssid_len:%d",params.ssid_len);
        wpa_printf(MSG_DEBUG, "nl80211ext: params->num_bridge:%d",params.num_bridge);
        wpa_hexdump(MSG_DEBUG, "nl80211ext: params->bridge[0]:%s",params.bridge[0],IFNAMSIZ + 1);
        wpa_hexdump(MSG_DEBUG, "nl80211ext: params->own_addr",params.own_addr, ETH_ALEN);

		if (wpa_drivers[i]->hapd_init) 
		{
		    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->hapd_init(&hapd,&params)");
			hapd.bss = wpa_drivers[i]->hapd_init(&hapd,&params);
			if (hapd.bss == NULL) 
			{
				printf("hapd_init Failed to initialize\n");
				return ;
			}		    
		}
        break;
    /* add new case here */
	case WIFLOW_NL80211_SET_OPERSTATE_REQUEST:
		if(wpa_drivers[i]->set_operstate)
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->set_operstate(void *priv,int state)");
			wpa_drivers[i]->set_operstate(hapd.bss, 1);
		}
		break;
	case WIFLOW_NL80211_HAPD_DEINIT_REQUEST:
		if(wpa_drivers[i]->hapd_deinit)
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->hapd_deinit(void *priv)");
			wpa_drivers[i]->hapd_deinit(hapd.bss);
		}
		break;
	case WIFLOW_NL80211_SEND_FRAME_REQUEST:
		ret = wpa_ieee80211_mgmt_parser(buf,MAX_BUF_LEN,&mgmt,&data_len,&encrypt);
		if(ret < 0)
        {
            fprintf(stderr,"wpa_ieee80211_mgmt_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
		if(wpa_drivers[i]->send_frame)
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->send_frame()");
			wpa_drivers[i]->send_frame(hapd.bss, (u8 *)&mgmt, data_len, encrypt);
		break;
	default:
		fprintf(stderr,"Unknown WiFlow PDU type,%s:%d\n",__FILE__,__LINE__);
	}  
    return;
}
