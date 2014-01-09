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
/*
 * 模仿hostapd调用driver
 * 注意call-down和driver call-up
 * call-down至少包括nl80211_global_init/nl80211_global_deinit,i802_init/i802_deinit
 * call-up至少包括wpa_supplicant_event,wpa_scan_results_free
 */
int main() 
{
    int i = 0;
    void * global_priv;
    struct hostapd_data hapd;
    struct wpa_init_params params;
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
    /* init nl80211 */ 
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
		printf("recv buf(params) from remote\n");
        /* recv buf(params) from remote */
        ret = recv(sockfd,buf,MAX_BUF_LEN,0);
        if(ret < 0)
        {
            fprintf(stderr,"Recv Error,%s:%d\n",__FILE__,__LINE__);  
        }
        printf("parse buf to params\n"); 
        /* parse buf to params */
        ret = wpa_init_params_parser(buf,ret,&params);
        if(ret < 0)
        {
            fprintf(stderr,"wpa_init_params_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
        wpa_printf(MSG_DEBUG, "nl80211ext: params->ifname:%s",params.ifname);
        wpa_printf(MSG_DEBUG, "nl80211ext: params->ssid:%s",params.ssid);
        wpa_printf(MSG_DEBUG, "nl80211ext: params->ssid_len:%d",params.ssid_len);

        params.global_priv = global_priv; 
        params.test_socket = NULL;
        params.use_pae_group_addr = 0;
		if (wpa_drivers[i]->hapd_init) 
		{
			hapd.bss = wpa_drivers[i]->hapd_init(&hapd,&params);
			if (hapd.bss == NULL) 
			{
				printf("hapd_init Failed to initialize\n");
				return -1;
			}		    
		}
		/* format hapd.bss to buf */
		buf_size = MAX_BUF_LEN;
		ret = i802_bss_format(buf,&buf_size,hapd.bss);
        if(ret < 0 || buf_size <= 0)
        {
            fprintf(stderr,"send Error,%s:%d\n",__FILE__,__LINE__);  
        }
		/* send buf(hapd.bss) */
        ret = send(sockfd,buf,buf_size,0);
        if(ret < 0)
        {
            fprintf(stderr,"send Error,%s:%d\n",__FILE__,__LINE__);  
        }		    
	}
	printf("NL80211 initialized\n");
	eloop_run();
    return 0;
}

void wpa_supplicant_event(void *ctx, enum wpa_event_type event,
			  union wpa_event_data *data)
{
    return;
}

void wpa_scan_results_free(struct wpa_scan_results *res)
{
    return;   
}