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
    unsigned char own_addr[ETH_ALEN];
};

extern struct wpa_driver_ops *wpa_drivers[];
struct wpa_driver_ap_params *my_params;
struct wpa_driver_capa *my_capa;
struct hostapd_freq_params *my_freq;

int main() 
{
    int i = 0;
    void * global_priv;
#if 0 
    unsigned char bssid[ETH_ALEN] = {0x20,0x4e,0x7f,0xda,0x23,0x6c};/*20:4e:7f:da:23:6c*/
    unsigned char own_addr[ETH_ALEN] = {0x20,0x4e,0x7f,0xda,0x23,0x6c};/*20:4e:7f:da:23:6c*/
    char iface[IFNAMSIZ + 1]  = "wlan1";
#else /* mengning's wlan card settings */
    unsigned char bssid[ETH_ALEN] = {0xc8,0x3a,0x35,0xc4,0x01,0xb8};/*c8:3a:35:c4:01:b8*/
    unsigned char own_addr[ETH_ALEN] = {0xc8,0x3a,0x35,0xc4,0x01,0xb8};/*c8:3a:35:c4:01:b8*/
    char iface[IFNAMSIZ + 1]  = "wlan2";
#endif
	char bridge[IFNAMSIZ + 1] = {0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};
	/* what it is? */
	unsigned char hd[59] ={0x80,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0x20,0x4e,0x7f,0xda,0x23,0x6c,0x20,0x4e,0x7f,0xda,0x23,0x6c, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x64,0x00,0x11,0x04,0x00,0x08,0x6d,0x65,0x6e,0x67,0x6e,0x69,0x6e,0x67,0x01,0x08,0x82,0x84, 0x8b,0x96,0x0c,0x12,0x18,0x24,0x03,0x01,0x0b};
    /* what it is? */
    unsigned char tl[55]={
        0x2a,0x01,0x04,0x32,0x04,0x30,0x48,0x60,0x6c,0x30,0x14,0x01,0x00,0x00,0x0f,0xac,0x02,0x01,0x00,0x00,0x0f,0xac,0x04,0x01,0x00,0x00,0x0f,0xac
        ,0x02,0x00,0x00,0xdd,0x16,0x00,0x50,0xf2,0x01,0x01,0x00,0x00,0x50,0xf2,0x02,0x01,0x00,0x00,0x50,0xf2,0x02,0x01,0x00,0x00,0x50,0xf2,0x02};

    struct hostapd_data hapd;
    memcpy(hapd.own_addr,own_addr,ETH_ALEN);
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
		    wpa_printf(MSG_DEBUG, "i = %d\n",i);
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
    
    /* get driver capability information(key/enc/auth...) */
	struct wpa_driver_capa capa;
	int ret;
	i = 0; 
	ret = wpa_drivers[i]->get_capa(hapd.bss,&capa);
    /*get supported hardware mode information(11a/b/g/ad ...) */
	u16 flags, num_modes;
	struct hostapd_hw_modes *modes;
	modes = wpa_drivers[i]->get_hw_feature_data(hapd.bss, &num_modes,&flags);
    /* Set kernel driver on given frequency (MHz) */
	struct hostapd_freq_params freq;
	freq.freq=2462; /* why? */
	freq.ht_enabled=0; /* why? */
	freq.sec_channel_offset=0; /* why? */
	wpa_drivers[i]->set_freq(hapd.bss,&freq);
    /* rts = request to send */
	int rts = 2347; /* why? */
	wpa_drivers[i]->set_rts(hapd.bss,rts);
	/* What is frag/WIPHY_FRAG_THRESHOLD ? */
	int frag = 2346; /* why? */
	wpa_drivers[i]->set_frag(hapd.bss, frag);

	unsigned char addr[ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff}; 
	const u8 *addr1 = addr;	
    /* DEL_STATION and flush all VLANs too */
	wpa_drivers[i]->flush(hapd.bss);

	wpa_drivers[i]->sta_deauth(hapd.bss,params.own_addr, addr1,2);

	wpa_drivers[i]->set_key(iface, hapd.bss,0, NULL,0,0,NULL, 0,NULL,0);
	wpa_drivers[i]->set_key(iface, hapd.bss,0, NULL,1,0,NULL, 0,NULL,0);
	wpa_drivers[i]->set_key(iface, hapd.bss,0, NULL,2,0,NULL, 0,NULL,0);
	wpa_drivers[i]->set_key(iface, hapd.bss,0, NULL,3,0,NULL, 0,NULL,0);

	my_params = (struct wpa_driver_ap_params *)malloc(sizeof(struct wpa_driver_ap_params));

	my_params->head_len = 59;
	my_params->head = malloc(my_params->head_len);
	memcpy(my_params->head, hd, 59);
	my_params->tail_len = 55;
	my_params->tail = malloc(my_params->tail_len);	
	memcpy(my_params->tail, tl, 55);
	my_params->dtim_period = 1;
	my_params->beacon_int = 100;
	my_params->basic_rates = malloc(48);
	my_params->proberesp_len = 0;
	my_params->proberesp = NULL;
	my_params->ssid_len = 8;
	my_params->ssid = malloc(my_params->ssid_len);
	unsigned char *ssid = "mengning";
	memcpy(my_params->ssid, ssid, my_params->ssid_len);
	my_params->hide_ssid = 0;
	my_params->pairwise_ciphers = 16;
	my_params->group_cipher = 8;
	my_params->key_mgmt_suites = 2;
	my_params->auth_algs = 3;
	my_params->wpa_version = 3;
	my_params->privacy = 1;
	my_params->beacon_ies = NULL;
	my_params->proberesp_ies = NULL;
	my_params->assocresp_ies = NULL;
	my_params->isolate = 0;
	my_params->cts_protect = 0;
	my_params->preamble = 0;
	my_params->short_slot_time = 1;
	my_params->ht_opmode = -1;
	my_params->interworking = 0;
	my_params->hessid = NULL;
	my_params->access_network_type = 0;
	my_params->ap_max_inactivity = 300;
	my_params->disable_dgaf = 0;
    /* enable beacon here ? */
	wpa_drivers[i]->set_ap(hapd.bss, my_params);

	wpa_drivers[i]->set_operstate(hapd.bss, 1);

	wpa_drivers[i]->set_tx_queue_params(hapd.bss,0,1,3,7,15);
	wpa_drivers[i]->set_tx_queue_params(hapd.bss,1,1,7,15,30);
	wpa_drivers[i]->set_tx_queue_params(hapd.bss,2,3,15,63,0);
	wpa_drivers[i]->set_tx_queue_params(hapd.bss,3,7,15,1023,0);

	eloop_run();

    return 0;
}

static void send_auth_reply(struct hostapd_data *hapd,
			    const u8 *dst, const u8 *bssid,
			    u16 auth_alg, u16 auth_transaction, u16 resp,
			    const u8 *ies, size_t ies_len)
{
	struct ieee80211_mgmt *reply;
	u8 *buf;
	size_t rlen;

	rlen = IEEE80211_HDRLEN + sizeof(reply->u.auth) + ies_len;
	buf = os_zalloc(rlen);
	if (buf == NULL)
		return;

	reply = (struct ieee80211_mgmt *) buf;
	reply->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					    WLAN_FC_STYPE_AUTH);
	os_memcpy(reply->da, dst, ETH_ALEN);
	os_memcpy(reply->sa, hapd->own_addr, ETH_ALEN);
	os_memcpy(reply->bssid, bssid, ETH_ALEN);

	reply->u.auth.auth_alg = host_to_le16(auth_alg);
	reply->u.auth.auth_transaction = host_to_le16(auth_transaction);
	reply->u.auth.status_code = host_to_le16(resp);

	if (ies && ies_len)
		os_memcpy(reply->u.auth.variable, ies, ies_len);

	wpa_printf(MSG_DEBUG, "authentication reply: STA=" MACSTR
		   " auth_alg=%d auth_transaction=%d resp=%d (IE len=%lu)",
		   MAC2STR(dst), auth_alg, auth_transaction,
		   resp, (unsigned long) ies_len);
	if (wpa_drivers[0]->send_mlme(hapd->bss, reply, rlen, 0) < 0)
		perror("send_auth_reply: send");

	os_free(buf);
}

void ieee802_11ext_mgmt(struct hostapd_data *hapd, const u8 *buf, size_t len)
		  //   struct hostapd_frame_info *fi)
{
	struct ieee80211_mgmt *mgmt;
	u16 fc, stype;

    unsigned char da1[30]={0xb0,0x00,0x00,0x00,0x54,0xea,0xa8,0x16,0x18,0x90,0x20,0x4e,0x7f,0xda,0x23,0x6c,0x20,0x4e,0x7f,0xda,0x23,0x6c,0x00,
        0x00,0x00,0x00,0x02,0x00,0x00,0x00};

    unsigned char da2[46]={0x10,0x00,0x00,0x00,0x54,0xea,0xa8,0x16,0x18,0x90,0x20,0x4e,0x7f,0xda,0x23,0x6c,0x20,0x4e,0x7f,0xda,0x23,0x6c,0x00,
        0x00,0x11,0x04,0x00,0x00,0x01,0xc0,0x01,0x08,0x82,0x84,0x8b,0x96,0x0c,0x12,0x18,0x24,0x32,0x04,0x30,0x48,0x60,0x6c};


	if (len < 24)
		return;

	mgmt = (struct ieee80211_mgmt *) buf;
	fc = le_to_host16(mgmt->frame_control);
	stype = WLAN_FC_GET_STYPE(fc);

	if (stype == WLAN_FC_STYPE_BEACON) {
        	printf("-----WLAN_FC_STYPE_BEACON\n");
		return;
	}


	if (stype == WLAN_FC_STYPE_PROBE_REQ) {
		printf("-----WLAN_FC_STYPE_PROBE_REQ\n");
		//handle_probe_req(hapd, mgmt, len, fi->ssi_signal);
		return;
	}

	int i = 0;
	switch (stype) {
	case WLAN_FC_STYPE_AUTH:
		wpa_printf(MSG_DEBUG, "mgmt::auth");
		/* send_auth_reply */
		/* send_auth_reply(hapd,
			    const u8 *dst, const u8 *bssid,
			    u16 auth_alg, u16 auth_transaction, u16 resp,
			    const u8 *ies, size_t ies_len);
	    */
		//wpa_drivers[i]->send_mlme(hapd->bss,buf,sizeof(struct ieee80211_mgmt),0);
		break;
	case WLAN_FC_STYPE_ASSOC_REQ:
		wpa_printf(MSG_DEBUG, "mgmt::assoc_req");
		wpa_drivers[i]->send_mlme(hapd->bss,da2,46,0);
		//handle_assoc(hapd, mgmt, len, 0);
		break;
	/*case WLAN_FC_STYPE_REASSOC_REQ:
		wpa_printf(MSG_DEBUG, "mgmt::reassoc_req");
		//handle_assoc(hapd, mgmt, len, 1);
		break;
	case WLAN_FC_STYPE_DISASSOC:
		wpa_printf(MSG_DEBUG, "mgmt::disassoc");
		//handle_disassoc(hapd, mgmt, len);
		break;
	case WLAN_FC_STYPE_DEAUTH:
		wpa_msg(hapd->msg_ctx, MSG_DEBUG, "mgmt::deauth");
		//handle_deauth(hapd, mgmt, len);
		break;
	case WLAN_FC_STYPE_ACTION:
		wpa_printf(MSG_DEBUG, "mgmt::action");
		//handle_action(hapd, mgmt, len);
		break; */
	default:
		wpa_printf(MSG_DEBUG, "-----default");
		break;
	}
}

void ieee802_11ext_mgmt_cb(struct hostapd_data *hapd, const u8 *buf, size_t len,
			u16 stype, int ok)
{
	const struct ieee80211_mgmt *mgmt;
	mgmt = (const struct ieee80211_mgmt *) buf;
	char iface[IFNAMSIZ + 1]  = "wlan1";
	unsigned char addr[ETH_ALEN] = {0x54,0xea,0xa8,0x16,0x18,0x90};/*54 ea a8 16 18 90*/
	unsigned char seq[32] = {0xa5,0xad,0x37,0x88,0xb8,0x5b,0x96,0x3f,0x8c,0x71,0x2a,0x46,0x4e,0x6e,0xad,0xcc,0xca,
            0x12,0x14,0xf3,0xa3,0x2d,0xba,0x7c,0xc4,0x12,0x33,0x6e,0x91,0xcb,0x62,0x6b};
	unsigned char own_addr[ETH_ALEN] = {0x20,0x4e,0x7f,0xda,0x23,0x6c};/*20:4e:7f:da:23:6c*/
	unsigned char data[99] = {0x02, 0x03, 0x00, 0x5f, 0x02, 0x00, 0x8a, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xae, 0x05, 0x1f, 0xa4, 0xdf, 0x43, 0x4e, 0xb7, 0x80, 0x34, 0xdb, 0x0e, 0x3d, 0x4e, 0xfd, 0xc2, 0xfa, 0xb4, 0xcd, 0xe1, 0x5f, 0x2d, 0x25, 0x30, 0x7d, 0x57, 0xdd, 0x2a, 0x88, 0xb0, 0x49, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	int i = 0;

	switch (stype) {
	case WLAN_FC_STYPE_AUTH:
		wpa_printf(MSG_DEBUG, "mgmt::auth cb");
		//handle_auth_cb(hapd, mgmt, len, ok);
		break;
	case WLAN_FC_STYPE_ASSOC_RESP:
		wpa_printf(MSG_DEBUG, "mgmt::assoc_resp cb");
		//handle_assoc_cb(hapd, mgmt, len, 0, ok);
	
		wpa_drivers[i]->set_key(iface,hapd->bss,0,addr,0,1,NULL,0,NULL,0);
		wpa_drivers[i]->sta_remove(hapd->bss,addr);
		//wpa_drivers[i]->sta_add();
		wpa_drivers[i]->sta_set_flags(hapd->bss,addr,4,4,-11);
		wpa_drivers[i]->set_key(iface,hapd->bss,0,addr,0,1,NULL,0,NULL,0);
		wpa_drivers[i]->set_key(iface,hapd->bss,0,addr,0,1,NULL,0,NULL,0);
		wpa_drivers[i]->sta_set_flags(hapd->bss,addr,4,0,-2);
		wpa_drivers[i]->set_key(iface,hapd->bss,2,addr,1,1,NULL,0,seq,32);
		wpa_drivers[i]->hapd_send_eapol(hapd->bss, addr, data,99,0,own_addr,4);

		break;
	/*case WLAN_FC_STYPE_REASSOC_RESP:
		wpa_printf(MSG_DEBUG, "mgmt::reassoc_resp cb");
		handle_assoc_cb(hapd, mgmt, len, 1, ok);
		break;
	case WLAN_FC_STYPE_PROBE_RESP:
		wpa_printf(MSG_EXCESSIVE, "mgmt::proberesp cb");
		break;
	case WLAN_FC_STYPE_DEAUTH:
		wpa_printf(MSG_DEBUG, "mgmt::deauth cb");
		handle_deauth_cb(hapd, mgmt, len, ok);
		break;
	case WLAN_FC_STYPE_DISASSOC:
		wpa_printf(MSG_DEBUG, "mgmt::disassoc cb");
		handle_disassoc_cb(hapd, mgmt, len, ok);
		break;
	case WLAN_FC_STYPE_ACTION:
		wpa_printf(MSG_DEBUG, "mgmt::action cb");
		break;*/
	default:
		printf("unknown mgmt cb frame subtype %d\n", stype);
		break;
	}
}


void wpa_supplicant_event(void *ctx, enum wpa_event_type event,
			  union wpa_event_data *data)
{ 
	struct hostapd_data *hapd = ctx;
#ifndef CONFIG_NO_STDOUT_DEBUG
	int level = MSG_DEBUG;

	if (event == EVENT_RX_MGMT && data->rx_mgmt.frame &&
	    data->rx_mgmt.frame_len >= 24) {
		const struct ieee80211_hdr *hdr;
		u16 fc;
		hdr = (const struct ieee80211_hdr *) data->rx_mgmt.frame;
		fc = le_to_host16(hdr->frame_control);
		if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_MGMT &&
		    WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_BEACON)
			level = MSG_EXCESSIVE;
	}

	wpa_dbg(hapd->msg_ctx, level, "Event %s (%d) received",
		event_to_string(event), event);
#endif /* CONFIG_NO_STDOUT_DEBUG */
    printf("\n___________________\n");

	switch (event) {
	case EVENT_TX_STATUS:
		printf("EVENT_TX_STATUS\n");
		switch (data->tx_status.type) {
		case WLAN_FC_TYPE_MGMT:
			printf("WLAN_FC_TYPE_MGMT:\n");
			ieee802_11ext_mgmt_cb(hapd->bss, data->tx_status.data,
					   data->tx_status.data_len,
					   data->tx_status.stype,
					   data->tx_status.ack);
			break;
		case WLAN_FC_TYPE_DATA:
			printf("WLAN_FC_TYPE_DATA:\n");
			/*hostapd_tx_status(hapd->bss, data->tx_status.dst,
					  data->tx_status.data,
					  data->tx_status.data_len,
					  data->tx_status.ack);*/
			break;
		}
		break;
	case EVENT_RX_MGMT:
		printf("EVENT_RX_MGMT\n");
		ieee802_11ext_mgmt(hapd->bss, data->rx_mgmt.frame,
					data->rx_mgmt.frame_len);		

		/*hostapd_mgmt_rx(hapd->bss, &data->rx_mgmt);*/
		break;
    case EVENT_EAPOL_TX_STATUS:
		printf("\nEVENT_EAPOL_TX_STATUS start\n");
		/*hostapd_eapol_tx_status(hapd->bss, data->eapol_tx_status.dst,
					data->eapol_tx_status.data,
					data->eapol_tx_status.data_len,
					data->eapol_tx_status.ack);*/
		printf("\nEVENT_EAPOL_TX_STATUS end\n");
		break;
	case EVENT_EAPOL_RX:
		//hostapd_event_eapol_rx(hapd, data->eapol_rx.src,
		//		       data->eapol_rx.data,
		//		       data->eapol_rx.data_len);
		break;

	default:
		wpa_printf(MSG_DEBUG, "Unknown event %d", event);
		break;
	}
}

void wpa_scan_results_free(struct wpa_scan_results *res)
{
    return;   
}



