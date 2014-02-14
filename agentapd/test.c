/*
 * Simu hostapd to call driver_nl80211
 * Copyright (c) 2013-2014, SSE@USTCSZ mengning <mengning@ustc.edu.cn>
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
/* TEST:simu hostapd call */
int main() 
{
    int i = 0;
    void * global_priv;
    unsigned char bssid[ETH_ALEN] = {0xc8,0x3a,0x35,0xc4,0x01,0xb8};/*c8:3a:35:c4:01:b8*/
    unsigned char own_addr[ETH_ALEN] = {0xc8,0x3a,0x35,0xc4,0x01,0xb8};/*c8:3a:35:c4:01:b8*/
    char iface[IFNAMSIZ + 1]  = "wlan2";;
	char bridge[IFNAMSIZ + 1] = {0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};
    struct hostapd_data hapd;
    struct wpa_init_params params;
	if (eloop_init()) 
	{
		wpa_printf(MSG_ERROR, "Failed to initialize event loop");
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
/*  init params in hostapd(main.c)
    params.global_priv = global.drv_priv[i];
	params.bssid = b;
	params.ifname = hapd->conf->iface;
	params.ssid = hapd->conf->ssid.ssid;
	params.ssid_len = hapd->conf->ssid.ssid_len;
	params.test_socket = hapd->conf->test_socket;
	params.use_pae_group_addr = hapd->conf->use_pae_group_addr;

	params.num_bridge = hapd->iface->num_bss;
	params.bridge = os_calloc(hapd->iface->num_bss, sizeof(char *));
	if (params.bridge == NULL)
		return -1;
	for (i = 0; i < hapd->iface->num_bss; i++) {
		struct hostapd_data *bss = hapd->iface->bss[i];
		if (bss->conf->bridge[0])
			params.bridge[i] = bss->conf->bridge;
	}

	params.own_addr = hapd->own_addr;
*/
		params.global_priv = global_priv; 
		params.bssid = bssid;
		params.ifname = iface;
		params.ssid = "mengning";
		params.ssid_len = 8;       
        params.test_socket = NULL;
        params.use_pae_group_addr = 0;
        params.num_bridge = 1;
        params.bridge = os_calloc(params.num_bridge, sizeof(char *));
    	if (params.bridge == NULL)
    		return -1;
    	/*params.bridge[0] = bridge;*/

        params.own_addr = own_addr;
        wpa_hexdump(MSG_DEBUG, "nl80211ext: params->bssid",params.bssid, ETH_ALEN);
        wpa_printf(MSG_DEBUG, "nl80211ext: params->ifname:%s",params.ifname);
        wpa_printf(MSG_DEBUG, "nl80211ext: params->ssid:%s",params.ssid);
        wpa_printf(MSG_DEBUG, "nl80211ext: params->ssid_len:%d",params.ssid_len);
        wpa_printf(MSG_DEBUG, "nl80211ext: params->num_bridge:%d",params.num_bridge);
        wpa_hexdump(MSG_DEBUG, "nl80211ext: params->bridge[0]:%s",params.bridge[0],IFNAMSIZ + 1);
        wpa_hexdump(MSG_DEBUG, "nl80211ext: params->own_addr",params.own_addr, ETH_ALEN);

        assert((wpa_drivers[i]->hapd_init != NULL));
		if (wpa_drivers[i]->hapd_init) 
		{
		    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->hapd_init(&hapd,&params)");
			hapd.bss = wpa_drivers[i]->hapd_init(&hapd,&params);
			if (hapd.bss == NULL) 
			{
				printf("hapd_init Failed to initialize\n");
				return -1;
			}		    
		}
        wpa_printf(MSG_DEBUG, "nl80211ext: hapd.bss->ifname:%s",hapd.bss->ifname);
    
	}
	printf("NL80211 initialized\n");
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


