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
#define MAX_BUF_LEN         1024

#include"driver.h"

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
        /* recv buf(params) from remote */
        ret = recv(sockfd,buf,MAX_BUF_LEN,0);
        if(ret > 0)
        {
            printf("Server send:%s\n",buf);   
        }
        /* parse buf to params */
             
        params.global_priv = global_priv;
		if (wpa_drivers[i]->hapd_init) 
		{
			hapd.bss = wpa_drivers[i]->hapd_init(&hapd,&params);
			if (hapd.bss == NULL) {
				printf("hapd_init Failed to initialize\n");
				return -1;
			}		    
		}
		/* format hapd.bss to buf */
		
		/* send buf(hapd.bss) */
        ret = send(sockfd,"hello",sizeof("hello"),0);
        if(ret > 0)
        {
            printf("send \"hello\" to %s:%d\n",(char*)inet_ntoa(serveraddr.sin_addr),ntohs(serveraddr.sin_port));
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