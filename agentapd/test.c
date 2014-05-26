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
#include<sys/ioctl.h>
#include<arpa/inet.h> /* internet socket */
#include<assert.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define PORT    5001
#define IP_ADDR "127.0.0.1"
#define MAX_CONNECT_QUEUE   1024

#include "driver.h"
#include "wiflow_protocol.h"
#include "common/wpa_common.h"
#include "wpa_auth_i.h"

#define RSNA_MAX_EAPOL_RETRIES 4
#define WLAN_SUPP_RATES_MAX 32
#define SHA1_MAC_LEN 20
#define POOL_WORDS 32
#define MD5_MAC_LEN 16
#define IEEE802_1X_TYPE_EAPOL_KEY 3
#define EAPOL_KEY_TYPE_RSN 2
#define EAPOL_KEY_TYPE_WPA 254
#define POOL_WORDS 32
#define POOL_WORDS_MASK (POOL_WORDS - 1)
#define POOL_TAP1 26
#define POOL_TAP2 20
#define POOL_TAP3 14
#define POOL_TAP4 7
#define POOL_TAP5 1
#define EXTRACT_LEN 16
#define MIN_READY_MARK 2
#define WLAN_EID_VENDOR_SPECIFIC 221
#define RSN_SELECTOR_LEN 4

#ifndef BIT
#define BIT(x) (1 << (x))
#endif

#define WPA_PUT_BE32(a, val)					\
	do {							\
		(a)[0] = (u8) ((((u32) (val)) >> 24) & 0xff);	\
		(a)[1] = (u8) ((((u32) (val)) >> 16) & 0xff);	\
		(a)[2] = (u8) ((((u32) (val)) >> 8) & 0xff);	\
		(a)[3] = (u8) (((u32) (val)) & 0xff);		\
	} while (0)

#define RSN_SELECTOR_PUT(a, val) WPA_PUT_BE32((u8 *) (a), (val))

struct ieee802_1x_hdr {
	u8 version;
	u8 type;
	be16 length;
	/* followed by length octets of data */
};

struct hostapd_data
{
    struct i802_bss * bss;
    unsigned char own_addr[ETH_ALEN];
    unsigned char bssid[ETH_ALEN];
    char iface[IFNAMSIZ + 1];
    char ssid[IFNAMSIZ + 1];
};

extern struct wpa_driver_ops *wpa_drivers[];
struct wpa_driver_ap_params *my_params;
struct wpa_driver_capa *my_capa;
struct hostapd_freq_params *my_freq;
struct wpa_state_machine *global_sm;

char iface[IFNAMSIZ + 1]  = "wlan1";
unsigned char broad_addr[ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff};
static unsigned int input_rotate = 0;
static unsigned int pool_pos = 0;
static u32 pool[POOL_WORDS];

int main() 
{
    int i = 0;
    void * global_priv;
    struct hostapd_data hapd;
    struct wpa_init_params params;

    unsigned char bssid[ETH_ALEN] = {0x20,0x4e,0x7f,0xda,0x23,0x6c};/*20:4e:7f:da:23:6c*/
    unsigned char own_addr[ETH_ALEN] = {0x20,0x4e,0x7f,0xda,0x23,0x6c};/*20:4e:7f:da:23:6c*/
    char ssid[IFNAMSIZ + 1] = "mengning";

    memcpy(hapd.own_addr,own_addr,ETH_ALEN);
    memcpy(hapd.bssid,own_addr,ETH_ALEN);  
    memcpy(hapd.iface,iface,strlen(iface));
    hapd.iface[strlen(iface)] = '\0';
    memcpy(hapd.ssid,ssid,strlen(ssid));

    char bridge[IFNAMSIZ + 1] = {0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};
	/* what it is? */
	const unsigned char hd[59] ={0x80,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,
	0x20,0x4e,0x7f,0xda,0x23,0x6c,/* MAC */
	0x20,0x4e,0x7f,0xda,0x23,0x6c,/* MAC */ 
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x64,0x00,0x11,0x04,
	0x00,0x08,0x6d,0x65,0x6e,0x67,0x6e,0x69,0x6e,0x67,/* SSID_LEN + SSID(mengning) */
	0x01,0x08,0x82,0x84, 0x8b,0x96,0x0c,0x12,0x18,0x24,0x03,0x01,0x0b}; 
    memcpy((void *)&hd[10],hapd.own_addr,ETH_ALEN);
    memcpy((void *)&hd[16],hapd.own_addr,ETH_ALEN);

    /* what it is? */
   const unsigned char tl[55]={0x2a,0x01,0x04,0x32,0x04,0x30,0x48,0x60,0x6c,
	0x30,0x14,0x01,0x00,0x00,0x0f,0xac,0x02,0x01,0x00,0x00,0x0f,0xac,0x04,0x01,
	0x00,0x00,0x0f,0xac,0x02,0x00,0x00,0xdd,0x16,0x00,0x50,0xf2,0x01,0x01,0x00,
	0x00,0x50,0xf2,0x02,0x01,0x00,0x00,0x50,0xf2,0x02,0x01,0x00,0x00,0x50,0xf2,0x02};

   unsigned char KEY[32] ={0x69,0x8e,0x84,0xf8,0xf5,0xb2,0x1c,0x87,0x17,0x5b,0x90,0x0b,0xb1,0xab,0x7a,
	0xd4,0x5b,0x61,0x01,0xb9,0x60,0x30,0x47,0xc0,0x71,0x30,0xa0,0x2c,0x83,0x0c,0xa4,0x54};
    
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
	const u8 *addr1 = broad_addr;	
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
	memcpy((void *)my_params->head, hd, 59);
	my_params->tail_len = 55;
	my_params->tail = malloc(my_params->tail_len);	
	memcpy((void *)my_params->tail, tl, 55);
	my_params->dtim_period = 1;
	my_params->beacon_int = 100;
	my_params->basic_rates = malloc(48);
	my_params->proberesp_len = 0;
	my_params->proberesp = NULL;
	my_params->ssid_len = 8;
	my_params->ssid = malloc(my_params->ssid_len);
	memcpy((void *)my_params->ssid, ssid, my_params->ssid_len);
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
	wpa_drivers[i]->set_key(iface, hapd.bss,2, broad_addr,1,1,NULL, 0,KEY,32);
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

	if (wpa_drivers[0]->send_mlme(hapd->bss, (const u8 *)reply, rlen, 0) < 0)
		perror("send_auth_reply: send");

	os_free(buf);
}

void ieee802_11ext_mgmt(struct hostapd_data *hapd, const u8 *buf, size_t len)
{
	struct ieee80211_mgmt *mgmt;
	u16 fc, stype;

    unsigned char da2[46]={0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x20,0x4e,0x7f,0xda,0x23,0x6c,0x20,0x4e,0x7f,0xda,0x23,0x6c,0x00,
        0x00,0x11,0x04,0x00,0x00,0x01,0xc0,0x01,0x08,0x82,0x84,0x8b,0x96,
	0x0c,0x12,0x18,0x24,0x32,0x04,0x30,0x48,0x60,0x6c};
	unsigned char addr[ETH_ALEN] = {0};
	if (len < 24)
		return;

	mgmt = (struct ieee80211_mgmt *) buf;
	fc = le_to_host16(mgmt->frame_control);
	stype = WLAN_FC_GET_STYPE(fc);
	if(memcmp(hapd->own_addr,mgmt->da,6)!=0)
	{	
		return;
	}
	memcpy(addr,mgmt->sa,6);

	if (stype == WLAN_FC_STYPE_BEACON) {
        	printf("-----WLAN_FC_STYPE_BEACON\n");
		return;
	}


	if (stype == WLAN_FC_STYPE_PROBE_REQ) {
		printf("-----WLAN_FC_STYPE_PROBE_REQ\n");
		return;
	}

	int i = 0;
	switch (stype) {
	case WLAN_FC_STYPE_AUTH:
		wpa_printf(MSG_DEBUG, "mgmt::auth");
		/* send_auth_reply */
		send_auth_reply(hapd,addr, hapd->own_addr,0, 2, 0,NULL, 0);
	  
		break;
	case WLAN_FC_STYPE_ASSOC_REQ:
		wpa_printf(MSG_DEBUG, "mgmt::assoc_req");
		memcpy(da2+4,mgmt->sa,6);
		wpa_hexdump(MSG_DEBUG, "------------da2",da2,46);
		wpa_drivers[i]->send_mlme(hapd->bss,da2,46,0);
		break;
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
	unsigned char addr[ETH_ALEN] = {0};
	unsigned char key[32] = {0xbe, 0x44, 0x92, 0xfb, 0x30, 0xf5, 0x5a, 0x1e, 0xb2, 
	0x93, 0xb4, 0x7a, 0xc7, 0xc9, 0x84, 0x4a, 0x79, 0xa8, 0x17, 0x93, 0xc5, 0xb5, 
	0x49, 0x3e, 0xc0, 0x0e, 0xb9, 0x6a, 0xad, 0x69, 0xd2, 0xa8};
	unsigned char data[99] = {0x02, 0x03, 0x00, 0x5f, 0x02, 0x00, 0x8a, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xae, 0x05, 0x1f, 0xa4, 0xdf, 0x43, 0x4e, 0xb7, 0x80, 0x34, 0xdb, 0x0e, 0x3d, 0x4e, 0xfd, 0xc2, 0xfa, 0xb4, 0xcd, 0xe1, 0x5f, 0x2d, 0x25, 0x30, 0x7d, 0x57, 0xdd, 0x2a, 0x88, 0xb0, 0x49, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	int i = 0;
	unsigned char supp[12] = {0x82,0x84,0x8b,0x96,0x24,0x30,0x48,0x6c,0x0c,0x12,0x18,0x60};
	struct hostapd_sta_add_params params;wpa_drivers[i];

	if(memcmp(hapd->own_addr,mgmt->sa,6)!=0)
	{	
		printf("memcmp(hapd->own_addr,mgmt->da,6)!=0\n");
		return;
	}
	memcpy(addr,mgmt->da,6);

	switch (stype) {
	case WLAN_FC_STYPE_AUTH:
		wpa_printf(MSG_DEBUG, "mgmt::auth cb");
		break;
	case WLAN_FC_STYPE_ASSOC_RESP:
		wpa_printf(MSG_DEBUG, "mgmt::assoc_resp cb");

		params.addr = addr;
		params.aid = 1;
		params.capability = 1041;
		params.supp_rates = malloc(12);
		memcpy((void *)params.supp_rates, supp, 12);	
		params.ht_capabilities = NULL;
		params.supp_rates_len = 12;
		params.listen_interval = 2;
		params.flags = 0;
		params.set = 0;
		params.qosinfo = 0;
		wpa_drivers[i]->sta_add(hapd->bss, &params);

		wpa_drivers[i]->sta_set_flags(hapd->bss,addr,4,4,-11);
		wpa_drivers[i]->set_key(iface,hapd->bss,0,addr,0,1,NULL,0,NULL,0);
		wpa_drivers[i]->set_key(iface,hapd->bss,0,addr,0,1,NULL,0,NULL,0);
		wpa_drivers[i]->sta_set_flags(hapd->bss,addr,4,0,-2);
		wpa_drivers[i]->set_key(iface,hapd->bss,0,addr,0,1,NULL,0,NULL,0);
		wpa_drivers[i]->set_key(iface,hapd->bss,2,broad_addr,1,1,NULL,0,key,32);
		wpa_drivers[i]->hapd_send_eapol(hapd->bss, addr, data,99,0,hapd->own_addr,4);

		free((void*)params.supp_rates);
		break;

	default:
		printf("unknown mgmt cb frame subtype %d\n", stype);
		break;
	}
}

int sha1_prf(const u8 *key, size_t key_len, const char *label,
	     const u8 *data, size_t data_len, u8 *buf, size_t buf_len)
{
	u8 counter = 0;
	size_t pos, plen;
	u8 hash[SHA1_MAC_LEN];
	size_t label_len = os_strlen(label) + 1;
	const unsigned char *addr[3];
	size_t len[3];

	addr[0] = (u8 *) label;
	len[0] = label_len;
	addr[1] = data;
	len[1] = data_len;
	addr[2] = &counter;
	len[2] = 1;
	
	pos = 0;
	while (pos < buf_len) {
		plen = buf_len - pos;
		if (plen >= SHA1_MAC_LEN) {
			if (hmac_sha1_vector(key, key_len, 3, addr, len,
					     &buf[pos]))
				return -1;
			pos += SHA1_MAC_LEN;
		} else {
			if (hmac_sha1_vector(key, key_len, 3, addr, len,
					     hash))
				return -1;
			os_memcpy(&buf[pos], hash, plen);
			break;
		}
		counter++;
	}
	return 0;
}


void wpa_pmk_to_ptk(const u8 *pmk, size_t pmk_len, const char *label,
		    const u8 *addr1, const u8 *addr2,
		    const u8 *nonce1, const u8 *nonce2,
		    u8 *ptk, size_t ptk_len, int use_sha256)
{
	
	u8 data[2 * ETH_ALEN + 2 * WPA_NONCE_LEN];
	if (os_memcmp(addr1, addr2, ETH_ALEN) < 0) {
		os_memcpy(data, addr1, ETH_ALEN);
		os_memcpy(data + ETH_ALEN, addr2, ETH_ALEN);
	} else {
		os_memcpy(data, addr2, ETH_ALEN);
		os_memcpy(data + ETH_ALEN, addr1, ETH_ALEN);
	}

	if (os_memcmp(nonce1, nonce2, WPA_NONCE_LEN) < 0) {
		os_memcpy(data + 2 * ETH_ALEN, nonce1, WPA_NONCE_LEN);
		os_memcpy(data + 2 * ETH_ALEN + WPA_NONCE_LEN, nonce2,
			  WPA_NONCE_LEN);
	} else {
		os_memcpy(data + 2 * ETH_ALEN, nonce2, WPA_NONCE_LEN);
		os_memcpy(data + 2 * ETH_ALEN + WPA_NONCE_LEN, nonce1,
			  WPA_NONCE_LEN);
	}
	
	sha1_prf(pmk, pmk_len, label, data, sizeof(data), ptk, ptk_len);
	wpa_printf(MSG_DEBUG, "WPA: PTK derivation - A1=" MACSTR " A2=" MACSTR,
		   MAC2STR(addr1), MAC2STR(addr2));
	wpa_hexdump(MSG_DEBUG, "WPA: Nonce1", nonce1, WPA_NONCE_LEN);
	wpa_hexdump(MSG_DEBUG, "WPA: Nonce2", nonce2, WPA_NONCE_LEN);
	wpa_hexdump(MSG_DEBUG, "WPA: PMK", pmk, pmk_len);
	wpa_hexdump(MSG_DEBUG, "WPA: PTK", ptk, ptk_len);
}

static int wpa_derive_ptk(struct wpa_state_machine *sm, const u8 *pmk,
			  struct wpa_ptk *ptk)
{
	size_t ptk_len = 48;
	wpa_pmk_to_ptk(pmk, PMK_LEN, "Pairwise key expansion",
		       sm->wpa_auth->addr, sm->addr, sm->ANonce, sm->SNonce,
		       (u8 *) ptk, ptk_len,
		       wpa_key_mgmt_sha256(2));

	return 0;
}

int hmac_sha1_vector(const u8 *key, size_t key_len, size_t num_elem,
		     const u8 *addr[], const size_t *len, u8 *mac)
{
	HMAC_CTX ctx;
	size_t i;
	unsigned int mdlen;
	int res;
	HMAC_CTX_init(&ctx);
#if OPENSSL_VERSION_NUMBER < 0x00909000
	HMAC_Init_ex(&ctx, key, key_len, EVP_sha1(), NULL);
#else /* openssl < 0.9.9 */
	if (HMAC_Init_ex(&ctx, key, key_len, EVP_sha1(), NULL) != 1) {		
		return -1;
	}
#endif /* openssl < 0.9.9 */
	for (i = 0; i < num_elem; i++)
		HMAC_Update(&ctx, addr[i], len[i]);

	mdlen = 20;
#if OPENSSL_VERSION_NUMBER < 0x00909000
	HMAC_Final(&ctx, mac, &mdlen);
	res = 1;
#else /* openssl < 0.9.9 */
	res = HMAC_Final(&ctx, mac, &mdlen);
#endif /* openssl < 0.9.9 */
	HMAC_CTX_cleanup(&ctx);
	return res = 0;
}

int hmac_sha1(const u8 *key, size_t key_len, const u8 *data, size_t data_len,
	       u8 *mac)
{
	return hmac_sha1_vector(key, key_len, 1, &data, &data_len, mac);
}


int wpa_eapol_key_mic(const u8 *key, int ver, const u8 *buf, size_t len,
		      u8 *mic)
{
	u8 hash[SHA1_MAC_LEN];
	if (hmac_sha1(key, 16, buf, len, hash))
		return -1;
	os_memcpy(mic, hash, MD5_MAC_LEN);
	return 0;
}


static int wpa_verify_key_mic(struct wpa_ptk *PTK, u8 *data, size_t data_len)
{
	struct ieee802_1x_hdr *hdr;
	struct wpa_eapol_key *key;
	u16 key_info;
	int ret = 0;
	u8 mic[16];

	if (data_len < sizeof(*hdr) + sizeof(*key))
		return -1;

	hdr = (struct ieee802_1x_hdr *) data;
	key = (struct wpa_eapol_key *) (hdr + 1);
	key_info = WPA_GET_BE16(key->key_info);//mark 1
	os_memcpy(mic, key->key_mic, 16);
	os_memset(key->key_mic, 0, 16);
	if (wpa_eapol_key_mic(PTK->kck, key_info & WPA_KEY_INFO_TYPE_MASK,
			      data, data_len, key->key_mic) ||
	    os_memcmp(mic, key->key_mic, 16) != 0)
		ret = -1;

	os_memcpy(key->key_mic, mic, 16);
	printf("ret: %d\n",ret);
	return ret;
}


void sm_machine_PTKCALCNEGOTIATING_entry(struct wpa_state_machine *sm)
{
	
	struct wpa_ptk PTK;
	int ok = 0;
	const u8 *pmk = NULL;
	unsigned char my_pmk[32] = {0x93,0xf0, 0xe8, 0xe5, 0x9d, 0x34, 0x87, 0xdf, 0x4b,
	0xb7, 0x06, 0x0d, 0xed, 0x68, 0xaf, 0xe4, 0x7a, 0x7d, 0xc9, 0xf8, 0x57, 0x9e, 
	0xcc, 0x7c, 0xc1, 0x7f, 0x91, 0x8b, 0xf8, 0x90, 0x22, 0x66};

	sm->EAPOLKeyReceived = FALSE;
	sm->update_snonce = FALSE;
	
	/* WPA with IEEE 802.1X: use the derived PMK from EAP
	 * WPA-PSK: iterate through possible PSKs and select the one matching
	 * the packet */
	// 搜索 need to print 
	for (;;) {
		if (wpa_key_mgmt_wpa_psk(sm->wpa_key_mgmt)) {
			printf("if (wpa_key_mgmt_wpa_psk(sm->wpa_key_mgmt))\n");
			pmk = my_pmk;
			if (pmk == NULL)
				break;
		} 

		wpa_derive_ptk(sm, pmk, &PTK);
		wpa_verify_key_mic(&PTK, sm->last_rx_eapol_key,
				       sm->last_rx_eapol_key_len);
	
		break;
	}

	sm->pending_1_of_4_timeout = 0;
	if (wpa_key_mgmt_wpa_psk(sm->wpa_key_mgmt)) {
		/* PSK may have changed from the previous choice, so update
		 * state machine data based on whatever PSK was selected here.
		 */
		os_memcpy(sm->PMK, pmk, PMK_LEN);
	}

	sm->MICVerified = TRUE;

	os_memcpy(&sm->PTK, &PTK, sizeof(PTK));
	sm->PTK_valid = TRUE;
}

void sm_machine_PTKCALCNEGOTIATING2_entry(struct wpa_state_machine *sm)
{
	sm->TimeoutCtr = 0;
}

u8 * wpa_add_kde(u8 *pos, u32 kde, const u8 *data, size_t data_len,
		 const u8 *data2, size_t data2_len)
{
	*pos++ = WLAN_EID_VENDOR_SPECIFIC;
	*pos++ = RSN_SELECTOR_LEN + data_len + data2_len;
	RSN_SELECTOR_PUT(pos, kde);
	pos += RSN_SELECTOR_LEN;
	os_memcpy(pos, data, data_len);
	pos += data_len;
	if (data2) {
		os_memcpy(pos, data2, data2_len);
		pos += data2_len;
	}
	return pos;
}

int wpa_cipher_key_len(int cipher)
{
	switch (cipher) {
	case WPA_CIPHER_CCMP:
	case WPA_CIPHER_GCMP:
		return 16;
	case WPA_CIPHER_TKIP:
		return 32;
	case WPA_CIPHER_WEP104:
		return 13;
	case WPA_CIPHER_WEP40:
		return 5;
	}

	return 0;
}

static inline int hostapd_drv_hapd_send_eapol(struct hostapd_data *hapd,
					      const u8 *addr, const u8 *data,
					      size_t data_len, int encrypt,
					      u32 flags)
{
	wpa_hexdump(MSG_DEBUG, " data: ", data, data_len);
	return wpa_drivers[0]->hapd_send_eapol(hapd->bss, addr, data,
					     data_len, encrypt,
					     hapd->own_addr, flags);
}


static int hostapd_wpa_auth_send_eapol(void *ctx, const u8 *addr,
				       const u8 *data, size_t data_len,
				       int encrypt)
{
	struct hostapd_data *hapd = ctx;
	u32 flags = 4;
	return hostapd_drv_hapd_send_eapol(hapd, addr, data, data_len,
					   encrypt, flags);
}


static int
wpa_auth_send_eapol(struct hostapd_data *hapd, struct wpa_authenticator *wpa_auth, const u8 *addr,
		    const u8 *data, size_t data_len, int encrypt)
{
	return hostapd_wpa_auth_send_eapol(hapd, addr, data, data_len,
				       encrypt);
}

static const EVP_CIPHER * aes_get_evp_cipher(size_t keylen)
{
	switch (keylen) {
	case 16:
		return EVP_aes_128_ecb();
	case 24:
		return EVP_aes_192_ecb();
	case 32:
		return EVP_aes_256_ecb();
	}

	return NULL;
}


void * aes_encrypt_init(const u8 *key, size_t len)
{
	EVP_CIPHER_CTX *ctx;
	const EVP_CIPHER *type;

	type = aes_get_evp_cipher(len);
	if (type == NULL)
		return NULL;

	ctx = os_malloc(sizeof(*ctx));
	if (ctx == NULL)
		return NULL;
	EVP_CIPHER_CTX_init(ctx);
	if (EVP_EncryptInit_ex(ctx, type, NULL, key, NULL) != 1) {
		os_free(ctx);
		return NULL;
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	return ctx;
}

void aes_encrypt_deinit(void *ctx)
{
	EVP_CIPHER_CTX *c = ctx;
	u8 buf[16];
	int len = sizeof(buf);
	if (EVP_EncryptFinal_ex(c, buf, &len) != 1) {
		wpa_printf(MSG_ERROR, "OpenSSL: EVP_EncryptFinal_ex failed: "
			   "%s", (char*)ERR_error_string(ERR_get_error(), NULL));
	}
	if (len != 0) {
		wpa_printf(MSG_ERROR, "OpenSSL: Unexpected padding length %d "
			   "in AES encrypt", len);
	}
	EVP_CIPHER_CTX_cleanup(c);
	os_free(c);
}

void aes_encrypt(void *ctx, const u8 *plain, u8 *crypt)
{
	EVP_CIPHER_CTX *c = ctx;
	int clen = 16;
	if (EVP_EncryptUpdate(c, crypt, &clen, plain, 16) != 1) {
		wpa_printf(MSG_ERROR, "OpenSSL: EVP_EncryptUpdate failed: %s",
			   (char *)ERR_error_string(ERR_get_error(), NULL));
	}
}

int aes_wrap(const u8 *kek, int n, const u8 *plain, u8 *cipher)
{
	u8 *a, *r, b[16];
	int i, j;
	void *ctx;

	a = cipher;
	r = cipher + 8;

	/* 1) Initialize variables. */
	os_memset(a, 0xa6, 8);
	os_memcpy(r, plain, 8 * n);

	ctx = aes_encrypt_init(kek, 16);
	if (ctx == NULL)
		return -1;

	/* 2) Calculate intermediate values.
	 * For j = 0 to 5
	 *     For i=1 to n
	 *         B = AES(K, A | R[i])
	 *         A = MSB(64, B) ^ t where t = (n*j)+i
	 *         R[i] = LSB(64, B)
	 */
	for (j = 0; j <= 5; j++) {
		r = cipher + 8;
		for (i = 1; i <= n; i++) {
			os_memcpy(b, a, 8);
			os_memcpy(b + 8, r, 8);
			aes_encrypt(ctx, b, b);
			os_memcpy(a, b, 8);
			a[7] ^= n * j + i;
			os_memcpy(r, b + 8, 8);
			r += 8;
		}
	}
	aes_encrypt_deinit(ctx);

	return 0;
}



void __wpa_send_eapol(struct hostapd_data *hapd, struct wpa_authenticator *wpa_auth,
		      struct wpa_state_machine *sm, int key_info,
		      const u8 *key_rsc, const u8 *nonce,
		      const u8 *kde, size_t kde_len,
		      int keyidx, int encr, int force_version)
{
	struct ieee802_1x_hdr *hdr;
	struct wpa_eapol_key *key;
	size_t len;
	int alg;
	int key_data_len, pad_len = 0;
	u8 *buf, *pos;
	int version, pairwise;
	int i;
	unsigned char counter[WPA_REPLAY_COUNTER_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
	len = sizeof(struct ieee802_1x_hdr) + sizeof(struct wpa_eapol_key);

	version = 2;
	pairwise = key_info & WPA_KEY_INFO_KEY_TYPE;
	key_data_len = kde_len;

	if ((version == WPA_KEY_INFO_TYPE_HMAC_SHA1_AES ||
	     version == WPA_KEY_INFO_TYPE_AES_128_CMAC) && encr) {
		pad_len = key_data_len % 8;
		if (pad_len)
			pad_len = 8 - pad_len;
		key_data_len += pad_len + 8;
	}
	len += key_data_len;
	hdr = os_zalloc(len);
	
	if (hdr == NULL)
		return;
	hdr->version = 2;
	hdr->type = IEEE802_1X_TYPE_EAPOL_KEY;
	hdr->length = host_to_be16(len  - sizeof(*hdr));
	key = (struct wpa_eapol_key *) (hdr + 1);

	key->type = 2;
	key_info |= version;
	if (encr && sm->wpa == WPA_VERSION_WPA2)
		key_info |= WPA_KEY_INFO_ENCR_KEY_DATA;
	if (sm->wpa != WPA_VERSION_WPA2)
		key_info |= keyidx << WPA_KEY_INFO_KEY_INDEX_SHIFT;
	WPA_PUT_BE16(key->key_info, key_info);

	alg = 16;
	WPA_PUT_BE16(key->key_length, wpa_cipher_key_len(alg));
	if (key_info & WPA_KEY_INFO_SMK_MESSAGE)
		WPA_PUT_BE16(key->key_length, 0);

	/* FIX: STSL: what to use as key_replay_counter? */
	for (i = RSNA_MAX_EAPOL_RETRIES - 1; i > 0; i--) {
		sm->key_replay[i].valid = sm->key_replay[i - 1].valid;
		os_memcpy(sm->key_replay[i].counter,
			  sm->key_replay[i - 1].counter,
			  WPA_REPLAY_COUNTER_LEN);
	}
	inc_byte_array(sm->key_replay[0].counter, WPA_REPLAY_COUNTER_LEN);
	os_memcpy(key->replay_counter, counter,
		  WPA_REPLAY_COUNTER_LEN);
	sm->key_replay[0].valid = TRUE;
	if (nonce)
		os_memcpy(key->key_nonce, nonce, WPA_NONCE_LEN);

	if (key_rsc)
		os_memcpy(key->key_rsc, key_rsc, WPA_KEY_RSC_LEN);

	if (kde && !encr) {
		os_memcpy(key + 1, kde, kde_len);
		WPA_PUT_BE16(key->key_data_length, kde_len);
	} else if (encr && kde) {
		buf = os_zalloc(key_data_len);
		if (buf == NULL) {
			os_free(hdr);
			return;
		}
		pos = buf;
		os_memcpy(pos, kde, kde_len);
		pos += kde_len;

		if (pad_len)
			*pos++ = 0xdd;

		wpa_hexdump_key(MSG_DEBUG, "Plaintext EAPOL-Key Key Data",
				buf, key_data_len);
		if (version == WPA_KEY_INFO_TYPE_HMAC_SHA1_AES ||
		    version == WPA_KEY_INFO_TYPE_AES_128_CMAC) {
			aes_wrap(sm->PTK.kek, (key_data_len - 8) / 8, buf,
				     (u8 *) (key + 1));
			WPA_PUT_BE16(key->key_data_length, key_data_len);
		}
		os_free(buf);
	}
	if (key_info & WPA_KEY_INFO_MIC) {
		if (!sm->PTK_valid) {
			os_free(hdr);
			return;
		}
		wpa_eapol_key_mic(sm->PTK.kck, version, (u8 *) hdr, len,
				  key->key_mic);
	}

	wpa_auth_send_eapol(hapd, wpa_auth, sm->addr, (u8 *) hdr, len,
			    sm->pairwise_set);
	os_free(hdr);
}



static void wpa_send_eapol(struct hostapd_data *hapd, struct wpa_authenticator *wpa_auth,
			   struct wpa_state_machine *sm, int key_info,
			   const u8 *key_rsc, const u8 *nonce,
			   const u8 *kde, size_t kde_len,
			   int keyidx, int encr)
{
	int timeout_ms;
	int pairwise = key_info & WPA_KEY_INFO_KEY_TYPE;
	int ctr;
	
	if (sm == NULL)
		return;
	printf("return2\n");
	__wpa_send_eapol(hapd, wpa_auth, sm, key_info, key_rsc, nonce, kde, kde_len,
			 keyidx, encr, 0);

	ctr = pairwise ? sm->TimeoutCtr : sm->GTimeoutCtr;
	if (pairwise && ctr == 1 && !(key_info & WPA_KEY_INFO_MIC))
		sm->pending_1_of_4_timeout = 1;
	wpa_printf(MSG_DEBUG, "WPA: Use EAPOL-Key timeout of %u ms (retry "
		   "counter %d)", timeout_ms, ctr);
}

static u32 __ROL32(u32 x, u32 y)
{
	return (x << (y & 31)) | (x >> (32 - (y & 31)));
}


static void random_mix_pool(const void *buf, size_t len)
{
	static const u32 twist[8] = {
		0x00000000, 0x3b6e20c8, 0x76dc4190, 0x4db26158,
		0xedb88320, 0xd6d6a3e8, 0x9b64c2b0, 0xa00ae278
	};
	const u8 *pos = buf;
	u32 w;

	wpa_hexdump_key(MSG_EXCESSIVE, "random_mix_pool", buf, len);

	while (len--) {
		w = __ROL32(*pos++, input_rotate & 31);
		input_rotate += pool_pos ? 7 : 14;
		pool_pos = (pool_pos - 1) & POOL_WORDS_MASK;
		w ^= pool[pool_pos];
		w ^= pool[(pool_pos + POOL_TAP1) & POOL_WORDS_MASK];
		w ^= pool[(pool_pos + POOL_TAP2) & POOL_WORDS_MASK];
		w ^= pool[(pool_pos + POOL_TAP3) & POOL_WORDS_MASK];
		w ^= pool[(pool_pos + POOL_TAP4) & POOL_WORDS_MASK];
		w ^= pool[(pool_pos + POOL_TAP5) & POOL_WORDS_MASK];
		pool[pool_pos] = (w >> 3) ^ twist[w & 7];
	}
}



static void random_extract(u8 *out)
{
	unsigned int i;
	u8 hash[SHA1_MAC_LEN];
	u32 *hash_ptr;
	u32 buf[POOL_WORDS / 2];
	u8 dummy_key[20] = {0xcf,0x0a,0xce,0x2e,0xa8,0x39,0xcf,0xfe,0x5c,0xf2,0xeb,0x55,0x7b,0x9a,0x60,0x32,0xe9,0xb2,0x87,0xad};
	

	/* First, add hash back to pool to make backtracking more difficult. */
	hmac_sha1(dummy_key, sizeof(dummy_key), (const u8 *) pool,
		  sizeof(pool), hash);
	random_mix_pool(hash, sizeof(hash));
	/* Hash half the pool to extra data */
	for (i = 0; i < POOL_WORDS / 2; i++)
		buf[i] = pool[(pool_pos - i) & POOL_WORDS_MASK];
	hmac_sha1(dummy_key, sizeof(dummy_key), (const u8 *) buf,
		  sizeof(buf), hash);

	hash_ptr = (u32 *) hash;
	hash_ptr[0] ^= hash_ptr[4];
	os_memcpy(out, hash, EXTRACT_LEN);
}



int random_get_bytes(void *buf, size_t len)
{
	int ret;
	u8 *bytes = buf;
	size_t left;

	/* Start with assumed strong randomness from OS */
	ret = os_get_random(buf, len);

	/* Mix in additional entropy extracted from the internal pool */
	left = len;
	while (left) {
		printf("random_get_bytes\n");
		size_t siz, i;
		u8 tmp[16];
		random_extract(tmp);
		siz = left > 16 ? 16 : left;
		for (i = 0; i < siz; i++)
			*bytes++ ^= tmp[i];
		left -= siz;
	}

//	if (entropy < len)
//		entropy = 0;
//	else
//		entropy -= len;

	return ret;
}


void sm_machine_PTKINITNEGOTIATING_entry(struct hostapd_data *hapd, struct wpa_state_machine *sm)
{
	u8 *_rsc, *gtk, *kde, *pos, dummy_gtk[32];
	size_t gtk_len, kde_len;
	struct wpa_group *gsm = sm->group;
	//u8 *wpa_ie;
	int wpa_ie_len, secure, keyidx, encr = 0;
	unsigned char wpa_ie[46] = {0x30,0x14,0x01,0x00,0x00,0x0f,0xac,0x02,0x01,0x00,0x00,0x0f,0xac,0x04,0x01,
	0x00,0x00,0x0f,0xac,0x02,0x00,0x00,0xdd,0x16,0x00,0x50,0xf2,0x01,0x01,0x00,0x00,0x50,
	0xf2,0x02,0x01,0x00,0x00,0x50,0xf2,0x02,0x01,0x00,0x00,0x50,0xf2,0x02};
	sm->TimeoutEvt = FALSE;

	sm->TimeoutCtr++;

	/* Send EAPOL(1, 1, 1, Pair, P, RSC, ANonce, MIC(PTK), RSNIE, [MDIE],
	   GTK[GN], IGTK, [FTIE], [TIE * 2])
	 */
	u8 rsc[WPA_KEY_RSC_LEN] = {0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	wpa_ie_len = 46;

	if (sm->wpa == WPA_VERSION_WPA2) {
		/* WPA2 send GTK in the 4-way handshake */
		secure = 1;
		gtk = NULL;
		gtk_len = 32;
		if (random_get_bytes(dummy_gtk, gtk_len) < 0)
			return;
		gtk = dummy_gtk;
		keyidx = 1;
		_rsc = rsc;
		encr = 1;
	} else {
		/* WPA does not include GTK in msg 3/4 */
		secure = 0;
		gtk = NULL;
		gtk_len = 0;
		keyidx = 0;
		_rsc = NULL;
		if (sm->rx_eapol_key_secure) {
			/*
			 * It looks like Windows 7 supplicant tries to use
			 * Secure bit in msg 2/4 after having reported Michael
			 * MIC failure and it then rejects the 4-way handshake
			 * if msg 3/4 does not set Secure bit. Work around this
			 * by setting the Secure bit here even in the case of
			 * WPA if the supplicant used it first.
			 */
			secure = 1;
		}
	}

	kde_len = 86;
	kde = os_malloc(kde_len);
	if (kde == NULL)
		return;
	pos = kde;
	os_memcpy(pos, wpa_ie, wpa_ie_len);
	pos += wpa_ie_len;
	if (gtk) {
		u8 hdr[2];
		hdr[0] = keyidx & 0x03;
		hdr[1] = 0;
		pos = wpa_add_kde(pos, RSN_KEY_DATA_GROUPKEY, hdr, 2,
				  gtk, gtk_len);
	}
	pos = 0;
	wpa_send_eapol(hapd, sm->wpa_auth, sm,
		       (secure ? WPA_KEY_INFO_SECURE : 0) | WPA_KEY_INFO_MIC |
		       WPA_KEY_INFO_ACK | WPA_KEY_INFO_INSTALL |
		       WPA_KEY_INFO_KEY_TYPE,
		       _rsc, sm->ANonce, kde, kde_len, keyidx, encr);
	os_free(kde);
}


void wpa_receive(struct hostapd_data *hapd, struct wpa_state_machine *sm, u8 *data, size_t data_len)
{
	struct ieee802_1x_hdr *hdr;
	struct wpa_eapol_key *key;
	u16 key_info, key_data_length;
	enum { PAIRWISE_2, PAIRWISE_4, GROUP_2, REQUEST,
	       SMK_M1, SMK_M3, SMK_ERROR } msg;
	int ft;
	const u8 *eapol_key_ie;
	size_t eapol_key_ie_len;
	unsigned char ANonce[32] = {0xae,0x05,0x1f,0xa4,0xdf,0x43,0x4e,0xb7,0x80,0x34,0xdb,0x0e,0x3d,0x4e,0xfd,0xc2, 				0xfa,0xb4,0xcd,0xe1,0x5f,0x2d,0x25,0x30,0x7d,0x57,0xdd,0x2a,0x88,0xb0,0x49,0xc0};

	if (data_len < sizeof(*hdr) + sizeof(*key))
		return;

	hdr = (struct ieee802_1x_hdr *) data;
	key = (struct wpa_eapol_key *) (hdr + 1);
	key_info = WPA_GET_BE16(key->key_info);
	key_data_length = WPA_GET_BE16(key->key_data_length);

	printf("key_data_length: %d\n",key_data_length);
	
	wpa_hexdump(MSG_DEBUG, "WPA: Received Key Nonce", key->key_nonce,
		    WPA_NONCE_LEN);
	wpa_hexdump(MSG_DEBUG, "WPA: Received Replay Counter",
		    key->replay_counter, WPA_REPLAY_COUNTER_LEN);


	sm->update_snonce = 1;
	sm->MICVerified = FALSE;
	
	if (key_data_length == 0) {
		u8 * key = (u8 *)malloc(16);
		memcpy(key, global_sm->PTK.tk1, 16);
		u8 * sta_addr = (u8 *)malloc(6);
		memcpy(sta_addr, global_sm->addr, 6);
		wpa_drivers[0]->set_key(iface,hapd->bss,3,sta_addr,0,1,NULL,0, key,16);
		wpa_drivers[0]->sta_set_flags(hapd->bss,sta_addr,5,1,-1);
		free(key);
		free(sta_addr);
	} 
	else 
	{	
		if (sm->last_rx_eapol_key != NULL) {

			free(sm->last_rx_eapol_key);
		}
		sm->last_rx_eapol_key = os_malloc(data_len);
		if (sm->last_rx_eapol_key == NULL)
			return;
		os_memcpy(sm->last_rx_eapol_key, data, data_len);
		sm->last_rx_eapol_key_len = data_len;
		sm->pairwise_set = 0;
		sm->wpa_key_mgmt = 2;
		sm->rx_eapol_key_secure = !!(key_info & WPA_KEY_INFO_SECURE);
		sm->EAPOLKeyReceived = TRUE;
		sm->EAPOLKeyPairwise = !!(key_info & WPA_KEY_INFO_KEY_TYPE);
		sm->EAPOLKeyRequest = !!(key_info & WPA_KEY_INFO_REQUEST);
		sm->wpa = WPA_VERSION_WPA2;
		os_memcpy(sm->SNonce, key->key_nonce, WPA_NONCE_LEN);
		os_memcpy(sm->ANonce, ANonce, WPA_NONCE_LEN);
		os_memcpy(sm->wpa_auth->addr, hapd->own_addr, ETH_ALEN);
 		sm_machine_PTKCALCNEGOTIATING_entry(sm);
		sm_machine_PTKCALCNEGOTIATING2_entry(sm);
		sm_machine_PTKINITNEGOTIATING_entry(hapd, sm);
		free(sm->last_rx_eapol_key);
		global_sm = sm;
	}		
}




void ieee802_1xext_receive(struct hostapd_data *hapd, const u8 *sa, const u8 *buf,
			size_t len)
{
	struct sta_info *sta;
	struct ieee802_1x_hdr *hdr;
	struct ieee802_1x_eapol_key *key;
	u16 datalen;
	struct rsn_pmksa_cache_entry *pmksa;
	struct wpa_state_machine *wpa_sm;

	wpa_sm = (struct wpa_state_machine *)malloc(sizeof(struct wpa_state_machine));
	memcpy(wpa_sm->addr,sa,ETH_ALEN);

	if (len < sizeof(*hdr)) {
		printf("   too short IEEE 802.1X packet\n");
		return;
	}

	hdr = (struct ieee802_1x_hdr *) buf;
	datalen = be_to_host16(hdr->length);

	if (len - sizeof(*hdr) > datalen) {
		wpa_printf(MSG_DEBUG, "   ignoring %lu extra octets after "
			   "IEEE 802.1X packet",
			   (unsigned long) len - sizeof(*hdr) - datalen);
	}

	wpa_receive(hapd, wpa_sm, (u8 *) hdr,sizeof(*hdr) + datalen);
	return;
}





void wpa_supplicant_event(void *ctx, enum wpa_event_type event,
			  union wpa_event_data *data)
{ 
	struct hostapd_data *hapd = ctx;
	static int count = 1;
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

	switch (event) {
	case EVENT_TX_STATUS:
		printf("EVENT_TX_STATUS\n");
		switch (data->tx_status.type) {
		case WLAN_FC_TYPE_MGMT:
			printf("WLAN_FC_TYPE_MGMT:\n");
			ieee802_11ext_mgmt_cb(hapd, data->tx_status.data,
					   data->tx_status.data_len,
					   data->tx_status.stype,
					   data->tx_status.ack);
			break;
		case WLAN_FC_TYPE_DATA:
			printf("WLAN_FC_TYPE_DATA:\n");
			break;
		}
		break;
	case EVENT_RX_MGMT:
		printf("EVENT_RX_MGMT\n");
		ieee802_11ext_mgmt(hapd, data->rx_mgmt.frame,
					data->rx_mgmt.frame_len);		
		break;
    case EVENT_EAPOL_TX_STATUS:
		printf("\nEVENT_EAPOL_TX_STATUS start\n");
		printf("\nEVENT_EAPOL_TX_STATUS end\n");
		break;
	case EVENT_EAPOL_RX:
		printf("\nEVENT_EAPOL_RX start\n");
		ieee802_1xext_receive(hapd, data->eapol_rx.src,data->eapol_rx.data,data->eapol_rx.data_len);
		printf("\nEVENT_EAPOL_RX end\n");
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



