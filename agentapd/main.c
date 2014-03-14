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
	u8 *own_addr;
	const char *ifname;
};

extern struct wpa_driver_ops *wpa_drivers[];
void * global_priv;
struct hostapd_data hapd;
int global_sockfd;

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
    global_sockfd = sockfd;
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
	int ret = 0;
	char buf[MAX_BUF_LEN];
	int buf_size;
	buf_size = MAX_BUF_LEN;
	ret = wpa_supplicant_data_format(buf, &buf_size, data, &event);
	if(ret < 0)
	{
		fprintf(stderr,"wpa_supplicant_rx_mgmt_format Error,%s:%d\n",__FILE__,__LINE__);
		return;
	}
	ret = send(global_sockfd,buf,buf_size,0);
	if(ret < 0)
	{
		fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
        	return;
   	}
}

void wpa_scan_results_free(struct wpa_scan_results *res)
{
    return;   
}

void handle_agent_read(int sock, void *eloop_ctx, void *sock_ctx)
{
    	int i = 0;
	size_t data_len = 0;
	int temp1 = 0,temp2 = 0;
	int encrypt = 0;
	int frag = -1;
	u32 uflags;
	enum wpa_driver_if_type type;
	u8 *addr, *data;
	char *bridge_ifname, *country;
    	char buf[MAX_BUF_LEN];
	u16 num_modes, flags;
    	struct wpa_init_params params;
	struct wpa_scan_results *scan_res;
	struct ieee80211_mgmt mgmt;
    	struct i802_bss * bss = (struct i802_bss *)eloop_ctx;
	struct hostapd_sta_add_params add_params;
	struct wpa_function_params func_params;
	struct hostapd_freq_params freq_data;
	struct wpa_set_tx_queue_params tx_params;
	struct wpa_driver_scan_params scan_params;
	struct wpa_set_key_params key_params;
	struct hostap_sta_driver_data sta_data;
	struct wpa_driver_ap_params ap_params;
	struct wpa_driver_capa capa;
	struct hostapd_hw_modes *remote_hw_modes;
//	struct hostapd_data *hapd = (struct hostapd_data *)eloop_ctx;
	int rts;
    /* read nl80211 commands from remote  */
	int buf_size = MAX_BUF_LEN;
	int ret;
	memset(buf,0,sizeof(buf));
    ret = recv(sock,buf,MAX_BUF_LEN,0);
    if(ret < 0)
    {
        fprintf(stderr,"Recv Error,%s:%d\n",__FILE__,__LINE__); 
    }
    struct wiflow_pdu *pdu = (struct wiflow_pdu*) buf;
	printf("pdu->type = %d\n",pdu->type);
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
	hapd.own_addr = params.own_addr;
	hapd.ifname = params.ifname;
    	if (params.bridge == NULL)
    	{
    	    fprintf(stderr,"os_calloc Error,%s:%d\n",__FILE__,__LINE__);
    		return ;
    	}	        
        /*wpa_hexdump(MSG_DEBUG, "nl80211ext: params->bssid",params.bssid, ETH_ALEN);
        wpa_printf(MSG_DEBUG, "nl80211ext: params->ifname:%s",params.ifname);
        wpa_printf(MSG_DEBUG, "nl80211ext: params->ssid:%s",params.ssid);
        wpa_printf(MSG_DEBUG, "nl80211ext: params->ssid_len:%d",params.ssid_len);
        wpa_printf(MSG_DEBUG, "nl80211ext: params->num_bridge:%d",params.num_bridge);
        wpa_hexdump(MSG_DEBUG, "nl80211ext: params->bridge[0]:%s",params.bridge[0],IFNAMSIZ + 1);
        wpa_hexdump(MSG_DEBUG, "nl80211ext: params->own_addr",params.own_addr, ETH_ALEN);
	*/
	for (i = 0; wpa_drivers[i]; i++) 
	{
		if (wpa_drivers[i]->hapd_init) 
		{
		    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->hapd_init()");
			hapd.bss = wpa_drivers[i]->hapd_init(&hapd,&params);
			if (hapd.bss == NULL) 
			{
				printf("hapd_init Failed to initialize\n");
				return ;
			}		    
		}
	}
		break;
    /* add new case here */
	case WIFLOW_NL80211_SET_OPERSTATE_REQUEST:
		if(wpa_drivers[i]->set_operstate)
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->set_operstate()");
			wpa_drivers[i]->set_operstate(hapd.bss, 1);
		}
		break;
	case WIFLOW_NL80211_HAPD_DEINIT_REQUEST:
		if(wpa_drivers[i]->hapd_deinit)
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->hapd_deinit()");
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
		}
		break;
	case WIFLOW_NL80211_I802_SET_WDS_STA_REQUEST:
		ret = wpa_i802_set_wds_sta_parser(buf,MAX_BUF_LEN,&addr,&temp1,&temp2,&bridge_ifname);
		if(ret < 0)
        {
            fprintf(stderr,"wpa_i802_set_wds_sta_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
		if(wpa_drivers[i]->set_wds_sta)
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->set_wds_sta()");
			wpa_drivers[i]->set_wds_sta(hapd.bss, addr, temp1, temp2, bridge_ifname);
		}
		break;
	case WIFLOW_NL80211_STA_ADD_REQUEST:
		ret = wpa_sta_add_parser(buf,MAX_BUF_LEN,&add_params);
        if(ret < 0)
        {
            fprintf(stderr,"wpa_sta_add_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
		if(wpa_drivers[i]->sta_add) 
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->sta_add()");
			wpa_drivers[i]->sta_add(hapd.bss, &add_params);
		}
		break;
	case WIFLOW_NL80211_IF_ADD_REQUEST1:
		ret = wpa_if_add_parser(buf, MAX_BUF_LEN, &func_params);
        if(ret < 0)
        {
            fprintf(stderr,"wpa_sta_add_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
		if(wpa_drivers[i]->if_add) 
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->if_add1()");
			wpa_drivers[i]->if_add(hapd.bss, func_params.type, func_params.ifname, func_params.addr,
							NULL, NULL, func_params.force_ifname, func_params.if_addr, NULL);
		}
		break;
	case WIFLOW_NL80211_IF_ADD_REQUEST2:
		ret = wpa_if_add_parser(buf, MAX_BUF_LEN, &func_params);
        if(ret < 0)
        {
            fprintf(stderr,"wpa_sta_add_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
		if(wpa_drivers[i]->if_add) 
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->if_add2()");
			wpa_drivers[i]->if_add(hapd.bss, func_params.type, func_params.ifname, func_params.addr,
				hapd.bss, (void*)&hapd.bss, func_params.force_ifname, func_params.if_addr, NULL);
		}
		break;
	case WIFLOW_NL80211_SET_FREQ_REQUEST:
		ret = wpa_set_freq_parser(buf, MAX_BUF_LEN, &freq_data);
        if(ret < 0)
        {
            fprintf(stderr,"wpa_set_freq_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
		if(wpa_drivers[i]->set_freq) 
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->set_freq()");
			wpa_drivers[i]->set_freq(hapd.bss,&freq_data);
		}
		break;
	case WIFLOW_NL80211_STA_SET_FLAGS_REQUEST:
		ret = wpa_sta_set_flags_parser(buf, MAX_BUF_LEN, &addr, &temp1, &temp2, &encrypt);
        if(ret < 0)
        {
            fprintf(stderr,"wpa_sta_set_flags_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
		if(wpa_drivers[i]->sta_set_flags) 
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->sta_set_flags()");
			wpa_drivers[i]->sta_set_flags(hapd.bss, addr, temp1, temp2, encrypt);
		}
		break;
	case WIFLOW_NL80211_SET_RTS_REQUEST:
	 	ret = wpa_set_rts_parser(buf, MAX_BUF_LEN, &rts);
	 	if(ret < 0)
	 	{
	 		fprintf(stderr,"wpa_set_rts_parser Error,%s:%d\n",__FILE__,__LINE__); 
	 	}
	 	if(wpa_drivers[i]->set_rts) 
	 	{
	 		wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->set_rts()");
	 		wpa_drivers[i]->set_rts(hapd.bss,rts);
	 	}
	 	break;
	case WIFLOW_NL80211_SEND_ACTION_REQUEST:
		ret = wpa_send_action_parser(buf, MAX_BUF_LEN,&temp1,
			&temp2,&addr, &data, &data_len);
        if(ret < 0)
        {
            fprintf(stderr,"wpa_send_action_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
		if(wpa_drivers[i]->send_action) 
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->send_action()");
			wpa_drivers[i]->send_action(hapd.bss,temp1,temp2,addr,hapd.own_addr,hapd.own_addr,data,data_len,0);
		}
		break;
	case WIFLOW_NL80211_SET_TX_QUEUE_PARAMS_REQUEST:
		ret = wpa_set_tx_queue_params_parser(buf, MAX_BUF_LEN, &tx_params);
        if(ret < 0)
        {
            fprintf(stderr,"wpa_send_action_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
		if(wpa_drivers[i]->set_tx_queue_params) 
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->set_tx_queue_params()");
			wpa_drivers[i]->set_tx_queue_params(hapd.bss,tx_params.queue, tx_params.aifs,
				tx_params.cw_min,tx_params.cw_max,tx_params.burst_time);
		}
		break;
	case WIFLOW_NL80211_SCAN2_REQUEST:
		ret = wpa_scan2_parser(buf, MAX_BUF_LEN, &scan_params);
        if(ret < 0)
        {
            fprintf(stderr,"wpa_scan2_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
		if(wpa_drivers[i]->scan2) 
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->set_tx_queue_params()");
			wpa_drivers[i]->scan2(hapd.bss,&scan_params);
		}
		break;
	case WIFLOW_NL80211_STA_DEAUTH_REQUEST:
		ret = wpa_sta_deauth_parser(buf, MAX_BUF_LEN, &addr, &temp1);
        if(ret < 0)
        {
            fprintf(stderr,"wpa_sta_deauth_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
		if(wpa_drivers[i]->sta_deauth) 
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->sta_deauth()");
			wpa_drivers[i]->sta_deauth(hapd.bss, hapd.own_addr, addr, temp1);
		}
		break;
	case WIFLOW_NL80211_STA_DISASSOC_REQUEST:
		ret = wpa_sta_disassoc_parser(buf, MAX_BUF_LEN, &addr, &temp1);
        if(ret < 0)
        {
            fprintf(stderr,"wpa_sta_disassoc_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
		if(wpa_drivers[i]->sta_disassoc) 
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->sta_disassoc()");
			wpa_drivers[i]->sta_disassoc(hapd.bss, hapd.own_addr, addr, temp1);
		}
		break;
	case WIFLOW_NL80211_SET_KEY_REQUEST:
		ret = wpa_set_key_parser(buf, MAX_BUF_LEN, &key_params);
        if(ret < 0)
        {
            fprintf(stderr,"wpa_set_key_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
		if(wpa_drivers[i]->sta_disassoc) 
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->set_key()");
			wpa_drivers[i]->set_key(hapd.ifname, hapd.bss, key_params.alg, key_params.addr,
				key_params.key_idx, key_params.set_tx, key_params.seq, 
				key_params.seq_len, key_params.key,key_params.key_len);
		}
		break;
	case WIFLOW_NL80211_SEND_MLME_REQUEST:
		ret = wpa_send_mlme_parser(buf, MAX_BUF_LEN, &data, &data_len, &temp1);
        if(ret < 0)
        {
            fprintf(stderr,"wpa_send_mlme_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
		if(wpa_drivers[i]->send_mlme) 
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->send_mlme()");
			wpa_drivers[i]->send_mlme(hapd.bss, data, data_len, 1);
		}
		break;
	/*return a struct to remote*/
	case WIFLOW_NL80211_GET_SCAN_RESULTS2_REQUEST:
		if(wpa_drivers[i]->get_scan_results2) 
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->get_scan_results2()");
			scan_res = wpa_drivers[i]->get_scan_results2(hapd.bss); /* struct *scan_res */
		}
		break;
	case WIFLOW_NL80211_GET_SEQNUM_REQUEST:
		ret = wpa_get_seqnum_parser(buf, MAX_BUF_LEN, &addr, &temp1, data);
        if(ret < 0)
        {
            fprintf(stderr,"wpa_get_seqnum_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
		if(wpa_drivers[i]->get_seqnum) 
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->get_seqnum()");
			wpa_drivers[i]->get_seqnum(hapd.ifname, hapd.bss, addr, temp1, data);
		}
		break;
	case WIFLOW_NL80211_SET_STA_VLAN_REQUEST:
		ret = wpa_set_sta_vlan_parser(buf, MAX_BUF_LEN, &addr, &temp1);
        if(ret < 0)
        {
            fprintf(stderr,"wpa_set_sta_vlan_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
		if(wpa_drivers[i]->set_sta_vlan) 
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->set_sta_vlan()");
			wpa_drivers[i]->set_sta_vlan(hapd.bss, addr, hapd.ifname, temp1);
		}
		break;
	case WIFLOW_NL80211_HAPD_SEND_EAPOL_REQUEST:
		ret = wpa_hapd_send_eapol_parser(buf,MAX_BUF_LEN, &addr, &data, &data_len, &encrypt, &uflags);
        if(ret < 0)
        {
            fprintf(stderr,"wpa_hapd_send_eapol_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
		if(wpa_drivers[i]->hapd_send_eapol) 
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->hapd_send_eapol()");
			wpa_drivers[i]->hapd_send_eapol(hapd.bss, addr, data, data_len, encrypt, hapd.own_addr, uflags);
		}
		break;
	case WIFLOW_NL80211_READ_STA_DATA_REQUEST:
		ret = wpa_read_sta_data_parser(buf,MAX_BUF_LEN, &sta_data, &addr);
        if(ret < 0)
        {
            fprintf(stderr,"wpa_read_sta_data_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
		if(wpa_drivers[i]->read_sta_data) 
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->read_sta_data()");
			wpa_drivers[i]->read_sta_data(hapd.bss, &sta_data, addr);
		}
		break;
	case WIFLOW_NL80211_POLL_CLIENT_REQUEST:
		ret = wpa_poll_client_parser(buf, MAX_BUF_LEN, &addr, &temp1);
        if(ret < 0)
        {
            fprintf(stderr,"wpa_poll_client_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
		if(wpa_drivers[i]->poll_client) 
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->poll_client()");
			wpa_drivers[i]->poll_client(hapd.bss, hapd.own_addr, addr, temp1);
		}
		break;
	case WIFLOW_NL80211_GET_INACT_SEC_REQUEST:
		ret = wpa_get_inact_sec_parser(buf, MAX_BUF_LEN, &addr);
        if(ret < 0)
        {
            fprintf(stderr,"wpa_get_inact_sec_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
		if(wpa_drivers[i]->get_inact_sec) 
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->get_inact_sec()");
			wpa_drivers[i]->get_inact_sec(hapd.bss, addr);
		}
		break;
	case WIFLOW_NL80211_STA_REMOVE_REQUEST:
		ret = wpa_sta_remove_parser(buf, MAX_BUF_LEN, &addr);
        if(ret < 0)
        {
            fprintf(stderr,"wpa_sta_remove_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
		if(wpa_drivers[i]->sta_remove) 
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->sta_remove()");
			wpa_drivers[i]->sta_remove(hapd.bss, addr);
		}
		break;
	case WIFLOW_NL80211_SET_AP_REQUEST:
		ret = wpa_set_ap_parser(buf, MAX_BUF_LEN, &ap_params);
        if(ret < 0)
        {
            fprintf(stderr,"wpa_sta_remove_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
		if(wpa_drivers[i]->set_ap) 
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->set_ap()");
			wpa_drivers[i]->set_ap(hapd.bss, &ap_params);
		}
		break;
	case WIFLOW_NL80211_SET_FRAG:
		frag = wpa_set_frag_parser(buf,MAX_BUF_LEN);	
        if(frag < 0)
        {
        	fprintf(stderr,"wpa_set_frag_parse Error,%s:%d\n",__FILE__,__LINE__); 
		}	
 		 wpa_drivers[i]->set_frag(hapd.bss, frag);
		 break;
	case WIFLOW_NL80211_IF_REMOVE:
		type =wpa_if_remove_parser(buf,MAX_BUF_LEN,&func_params);
		if(type < 0)
		{
			fprintf(stderr,"wpa_if_remove__parse Error,%s:%d\n",__FILE__,__LINE__); 
		}
		 wpa_drivers[i]->if_remove(hapd.bss,type,func_params.ifname);
		 break;
	case  WIFLOW_NL80211_i802_FLUSH_REQUEST:
		if(wpa_drivers[i]->flush) 
		{
			wpa_printf(MSG_DEBUG, "nl80211ext: wpa_drivers[i]->flush()");
			wpa_drivers[i]->flush(hapd.bss);
		}
		break;	
	case WIFLOW_INIT_CAPA_REQUEST:
		if(wpa_drivers[i]->get_capa(hapd.bss,&capa) != 0)
		{
			fprintf(stderr,"get_capa Error,%s:%d\n",__FILE__,__LINE__); 
		}
		ret = wpa_init_capa_format(buf, &buf_size, &capa);
		if(ret < 0 || buf_size <= 0)
		{
			fprintf(stderr,"wiflow_pdu_format Error,%s:%d\n",__FILE__,__LINE__);  
		}
		/*ret = send(sock,buf,buf_size,0);
		if(ret < 0)
		{
			fprintf(stderr,"send Error,%s:%d\n",__FILE__,__LINE__);  
    	}*/
		break;
	case WIFLOW_SET_COUNTRY:
		ret = wpa_set_country_parser(buf,buf_size,&country);
        if(ret < 0)
        {
        	fprintf(stderr,"wpa_init_params_parser Error,%s:%d\n",__FILE__,__LINE__); 
        }
		if(wpa_drivers[i]->set_country(hapd.bss, country) != 0)
		{
			fprintf(stderr,"set_country Error,%s:%d\n",__FILE__,__LINE__);  
		}
		break;
	case WPA_GET_HW_MODE_REQUEST:
		printf("WPA_GET_HW_MODE_REQUEST\n");
		ret = wpa_get_hw_feature_parser(buf, buf_size, &num_modes, &flags);
		if(ret < 0)
		{
			fprintf(stderr,"wiflow_pdu_format Error,%s:%d\n",__FILE__,__LINE__);  
		}
		if((remote_hw_modes = wpa_drivers[i]->get_hw_feature_data(hapd.bss, &num_modes, &flags)) == NULL)
		{
			fprintf(stderr,"get_hw_feature_data Error,%s:%d\n",__FILE__,__LINE__); 
		}
		/*ret = remote_hw_modes_format(buf, &buf_size, remote_hw_modes);
		if(ret < 0)
        	{
           		fprintf(stderr,"remote_hw_modes_format Error,%s:%d\n",__FILE__,__LINE__); 
       		}
		ret = send(sock,buf,buf_size,0);
		if(ret < 0)
		{
			fprintf(stderr,"send Error,%s:%d\n",__FILE__,__LINE__);  
    		}
		break;*/
		break;
	default:
		fprintf(stderr,"Unknown WiFlow PDU type,%s:%d\n",__FILE__,__LINE__);
		break;
	}  
    return;
}
