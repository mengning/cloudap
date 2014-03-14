/*
 * Driver interaction with socket to Linux nl80211/cfg80211
 * Copyright (c) 2013-2014, SSE@USTCSZ mengning <mengning@ustc.edu.cn>
 *
 * driver_nl80211ext.c(socket server) - agentapd(socket client)with Linux nl80211/cfg80211
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/rtnetlink.h>
#include <netpacket/packet.h>
#include <linux/filter.h>
#include <linux/errqueue.h>

#include<stdio.h>
#include<arpa/inet.h>
#include<assert.h>
#include<string.h>

#include "nl80211_copy.h"

#include "common.h"
#include "eloop.h"
#include "utils/list.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "l2_packet/l2_packet.h"
#include "netlink.h"
#include "linux_ioctl.h"
#include "radiotap.h"
#include "radiotap_iter.h"
#include "rfkill.h"
#include "driver.h"
#include "wiflow_protocol.h"
#include "ap/hostapd.h"


#define PORT                    5001
#define IP_ADDR                 "127.0.0.1"
#define MAX_CONNECT_QUEUE       1024

struct hostapd_data *ghapd;
int accept_fd = -1;
int agentfd = -1;
char buf[MAX_BUF_LEN];
struct i802_bss gbss;
void *global_ctx;

struct nl80211_global {
	struct dl_list interfaces;
	int if_add_ifindex;
	struct netlink_data *netlink;
	struct nl_cb *nl_cb;
	struct nl_handle *nl;
	int nl80211_id;
	int ioctl_sock; /* socket for ioctl() use */

	struct nl_handle *nl_event;
};

struct nl80211_wiphy_data {
	struct dl_list list;
	struct dl_list bsss;
	struct dl_list drvs;

	struct nl_handle *nl_beacons;
	struct nl_cb *nl_cb;

	int wiphy_idx;
};

static void nl80211_global_deinit(void *priv);
static void wpa_driver_nl80211_deinit(void *priv);

struct wpa_driver_nl80211_data {
	struct nl80211_global *global;
	struct dl_list list;
	struct dl_list wiphy_list;
	char phyname[32];
	void *ctx;
	int ifindex;
	int if_removed;
	int if_disabled;
	int ignore_if_down_event;
	struct rfkill_data *rfkill;
	struct wpa_driver_capa capa;
	int has_capability;

	int operstate;

	int scan_complete_events;

	struct nl_cb *nl_cb;

	u8 auth_bssid[ETH_ALEN];
	u8 bssid[ETH_ALEN];
	int associated;
	u8 ssid[32];
	size_t ssid_len;
	enum nl80211_iftype nlmode;
	enum nl80211_iftype ap_scan_as_station;
	unsigned int assoc_freq;

	int monitor_sock;
	int monitor_ifidx;
	int monitor_refcount;

	unsigned int disabled_11b_rates:1;
	unsigned int pending_remain_on_chan:1;
	unsigned int in_interface_list:1;
	unsigned int device_ap_sme:1;
	unsigned int poll_command_supported:1;
	unsigned int data_tx_status:1;
	unsigned int scan_for_auth:1;
	unsigned int retry_auth:1;
	unsigned int use_monitor:1;
	unsigned int ignore_next_local_disconnect:1;

	u64 remain_on_chan_cookie;
	u64 send_action_cookie;

	unsigned int last_mgmt_freq;

	struct wpa_driver_scan_filter *filter_ssids;
	size_t num_filter_ssids;

	struct i802_bss first_bss;

	int eapol_tx_sock;

#ifdef HOSTAPD
	int eapol_sock; /* socket for EAPOL frames */

	int default_if_indices[16];
	int *if_indices;
	int num_if_indices;

	int last_freq;
	int last_freq_ht;
#endif /* HOSTAPD */

	/* From failed authentication command */
	int auth_freq;
	u8 auth_bssid_[ETH_ALEN];
	u8 auth_ssid[32];
	size_t auth_ssid_len;
	int auth_alg;
	u8 *auth_ie;
	size_t auth_ie_len;
	u8 auth_wep_key[4][16];
	size_t auth_wep_key_len[4];
	int auth_wep_tx_keyidx;
	int auth_local_state_change;
	int auth_p2p;
};

static int wpa_driver_nl80211_get_bssid(void *priv, u8 *bssid)
{
    /* wpa_hexdump(MSG_MSGDUMP, "nl80211ext: wpa_driver_nl80211_get_bssid(void *priv, u8 *bssid)",
		    bssid, ETH_ALEN);*/
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return 0;
}


static int wpa_driver_nl80211_get_ssid(void *priv, u8 *ssid)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return strlen("mengning");
}

/**
 * wpa_driver_nl80211_set_country - ask nl80211 to set the regulatory domain
 * @priv: driver_nl80211 private data
 * @alpha2_arg: country to which to switch to
 * Returns: 0 on success, -1 on failure
 *
 * This asks nl80211 to set the regulatory domain for given
 * country ISO / IEC alpha2.
 */
static int wpa_driver_nl80211_set_country(void *priv, const char *alpha2_arg)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int ret;
	int buf_size = MAX_BUF_LEN;
	
	memset(buf, 0, MAX_BUF_LEN);
	ret = wpa_set_country_format(buf,&buf_size,alpha2_arg);
    if(ret < 0 || buf_size <= 0)
    {
        fprintf(stderr,"wiflow_pdu_format Error,%s:%d\n",__FILE__,__LINE__);  
    }
	ret = send(agentfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"send Error,%s:%d\n",__FILE__,__LINE__);  
    }
	return 0;

}

/**
 * wpa_driver_nl80211_init - Initialize nl80211 driver interface
 * @ctx: context to be used when calling wpa_supplicant functions,
 * e.g., wpa_supplicant_event()
 * @ifname: interface name, e.g., wlan0
 * @global_priv: private driver global data from global_init()
 * Returns: Pointer to private data, %NULL on failure
 */
static void * wpa_driver_nl80211_init(void *ctx, const char *ifname,
				      void *global_priv)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return NULL;
}

/**
 * wpa_driver_nl80211_deinit - Deinitialize nl80211 driver interface
 * @priv: Pointer to private nl80211 data from wpa_driver_nl80211_init()
 *
 * Shut down driver interface and processing of driver events. Free
 * private data buffer if one was allocated in wpa_driver_nl80211_init().
 */
static void wpa_driver_nl80211_deinit(void *priv)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
}

/**
 * wpa_driver_nl80211_scan - Request the driver to initiate scan
 * @priv: Pointer to private driver data from wpa_driver_nl80211_init()
 * @params: Scan parameters
 * Returns: 0 on success, -1 on failure
 */
static int wpa_driver_nl80211_scan(void *priv,
				   struct wpa_driver_scan_params *params, int data_len)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int buf_size = 0;
	int ret = 0;
    /* format  params to buf */
    buf_size = MAX_BUF_LEN;
    ret = wpa_scan2_format(buf, &buf_size, params, data_len);
    if(ret < 0)
    {
        fprintf(stderr,"wpa_scan2_format Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_scan2_format buf_size:%d",buf_size);
    /* send buf(params) */
    ret = send(agentfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
	return 0;
}


/**
 * wpa_driver_nl80211_sched_scan - Initiate a scheduled scan
 * @priv: Pointer to private driver data from wpa_driver_nl80211_init()
 * @params: Scan parameters
 * @interval: Interval between scan cycles in milliseconds
 * Returns: 0 on success, -1 on failure or if not supported
 */
static int wpa_driver_nl80211_sched_scan(void *priv,
					 struct wpa_driver_scan_params *params,
					 u32 interval)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return 0;
}


/**
 * wpa_driver_nl80211_stop_sched_scan - Stop a scheduled scan
 * @priv: Pointer to private driver data from wpa_driver_nl80211_init()
 * Returns: 0 on success, -1 on failure or if not supported
 */
static int wpa_driver_nl80211_stop_sched_scan(void *priv)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return 0;
}

static int wpa_driver_nl80211_set_key(const char *ifname, void *priv,
				      enum wpa_alg alg, const u8 *addr,
				      int key_idx, int set_tx,
				      const u8 *seq, size_t seq_len,
				      const u8 *key, size_t key_len)
{
	wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int buf_size = 0;
	int ret = 0;
    /* format  argc to buf */
    buf_size = MAX_BUF_LEN;
    ret = wpa_set_key_format(buf, &buf_size, alg, addr, key_idx, set_tx, seq, seq_len, key, key_len);
    if(ret < 0)
    {
        fprintf(stderr,"wpa_set_key_format Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_set_key_format buf_size:%d",buf_size);
    /* send buf(argc) */
    ret = send(agentfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
	return 0;
}

static int wpa_driver_nl80211_deauthenticate(void *priv, const u8 *addr,
					     int reason_code)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return 0;
}

static int wpa_driver_nl80211_authenticate(
	void *priv, struct wpa_driver_auth_params *params)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return 0;
}

static struct hostapd_hw_modes *
wpa_driver_nl80211_get_hw_feature_data(void *priv, u16 *num_modes, u16 *flags)
{
		wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
		int ret;
		int buf_size = MAX_BUF_LEN;
		struct hostapd_hw_modes *local_hw_mode = NULL;
		/*local_hw_mode = (struct hostapd_hw_modes *)malloc(200);*/
		memset(buf, 0, MAX_BUF_LEN);
		ret = wpa_get_hw_feature_format(buf,&buf_size,num_modes,flags);
		if(ret < 0 || buf_size <= 0)
		{
			fprintf(stderr,"wiflow_pdu_format Error,%s:%d\n",__FILE__,__LINE__);  
			goto err;
		}
		/*ret = send(agentfd,buf,buf_size,0);
		if(ret < 0)
		{
			fprintf(stderr,"send Error,%s:%d\n",__FILE__,__LINE__);  
			goto err;
		}
		*/
		*num_modes = 2;
		*flags = 0;
		local_hw_mode = local_default_hw_mode();
		if(local_hw_mode == NULL)
		{
			fprintf(stderr,"local_default_hw_mode Error,%s:%d\n",__FILE__,__LINE__);
			return NULL;
		}
		return local_hw_mode;
	err:
		return NULL;

}

static int wpa_driver_nl80211_send_mlme(void *priv, const u8 *data,
					size_t data_len, int noack)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int buf_size = 0;
	int ret = 0;
    /* format  argc to buf */
    buf_size = MAX_BUF_LEN;
    memset(buf,0,sizeof(buf));
    ret = wpa_send_mlme_format(buf, &buf_size, data, data_len, noack);
    if(ret < 0)
    {
        fprintf(stderr,"wpa_send_mlme_format Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_send_mlme_format buf_size:%d",buf_size);
    /* send buf(params) */
    ret = send(agentfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
	return 0;
}

static int wpa_driver_nl80211_set_ap(void *priv,
				     struct wpa_driver_ap_params *params)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int buf_size = 0;
	int ret = 0;
    /* format  params to buf */
    buf_size = MAX_BUF_LEN;
    memset(buf,0, sizeof(buf));
    ret = wpa_set_ap_format(buf, &buf_size, params);
    if(ret < 0)
    {
        fprintf(stderr,"wpa_set_ap_format Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_set_ap_format buf_size:%d",buf_size);
    /* send buf(params) */
    ret = send(agentfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
	return 0;
}

static int wpa_driver_nl80211_sta_add(void *priv,
				      struct hostapd_sta_add_params *params)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );  
	int buf_size = 0;
	int ret = 0;
    /* format  params to buf */
    buf_size = MAX_BUF_LEN;
    ret = wpa_sta_add_format(buf, &buf_size, params);
    if(ret < 0)
    {
        fprintf(stderr,"wpa_sta_add_format Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_sta_add_format buf_size:%d",buf_size);
    /* send buf(params) */
    ret = send(agentfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
	return 0;
}


static int wpa_driver_nl80211_sta_remove(void *priv, const u8 *addr)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int buf_size = 0;
	int ret = 0;
    /* format  func argc to buf */
    buf_size = MAX_BUF_LEN;
    ret = wpa_sta_remove_format(buf, &buf_size, addr);
    if(ret < 0)
    {
        fprintf(stderr,"wpa_sta_remove_format Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_get_inact_sec_format buf_size:%d",buf_size);
    /* send buf(argc) */
    ret = send(agentfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
	return 0;
}


static const u8 rfc1042_header[6] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };

static int wpa_driver_nl80211_hapd_send_eapol(
	void *priv, const u8 *addr, const u8 *data,
	size_t data_len, int encrypt, const u8 *own_addr, u32 flags)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int buf_size = 0;
	int ret = 0;
    /* format  argc to buf */
    buf_size = MAX_BUF_LEN;
    ret = wpa_hapd_send_eapol_format(buf,&buf_size, addr, data, data_len, encrypt, flags);
    if(ret < 0)
    {
        fprintf(stderr,"wpa_sta_add_format Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_sta_add_format buf_size:%d",buf_size);
    /* send buf(argc) */
    ret = send(agentfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
	return 0;
}


static int wpa_driver_nl80211_sta_set_flags(void *priv, const u8 *addr,
					    int total_flags,
					    int flags_or, int flags_and)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int buf_size = 0;
	int ret = 0;
    /* format  argc to buf */
    buf_size = MAX_BUF_LEN;
    ret = wpa_sta_set_flags_format(buf, &buf_size, addr, total_flags, flags_or, flags_and);
    if(ret < 0)
    {
        fprintf(stderr,"wpa_sta_set_flags_format Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_sta_set_flags_format buf_size:%d",buf_size);
    /* send buf(argc) */
    ret = send(agentfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
	return 0;
}

static int wpa_driver_nl80211_associate(
	void *priv, struct wpa_driver_associate_params *params)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return 0;
}

static int wpa_driver_nl80211_get_capa(void *priv,
				       struct wpa_driver_capa *capa)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return 0;
}


static int wpa_driver_nl80211_set_operstate(void *priv, int state)
{
	wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int buf_size = 0;
	int ret = 0;
    /* format  type to buf */
    buf_size = MAX_BUF_LEN;
    ret = wiflow_pdu_format(buf,&buf_size, WIFLOW_NL80211_SET_OPERSTATE_REQUEST);
	if(ret < 0 || buf_size <= 0)
    {
        fprintf(stderr,"wiflow_pdu_format Error,%s:%d\n",__FILE__,__LINE__);  
    }
	ret = send(agentfd,buf,buf_size,0);
	if(ret < 0)
    {
        fprintf(stderr,"send Error,%s:%d\n",__FILE__,__LINE__);  
    }
	return 0;
}


static int wpa_driver_nl80211_set_supp_port(void *priv, int authorized)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return 0;
}


/* Set kernel driver on given frequency (MHz) */
static int i802_set_freq(void *priv, struct hostapd_freq_params *freq)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int buf_size = 0;
	int ret = 0;
    /* format  freq to buf */
    buf_size = MAX_BUF_LEN;
    freq->freq = 2462;
    freq->mode = 1;
    freq->channel=11;
    freq->ht_enabled = 0;
    freq->sec_channel_offset = 0;
    ret = wpa_set_freq_format(buf, &buf_size, freq);
    if(ret < 0)
    {
        fprintf(stderr,"wpa_set_freq_format Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_set_freq_format buf_size:%d",buf_size);
    /* send buf(freq) */
    ret = send(agentfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
	return 0;
}


#if defined(HOSTAPD) || defined(CONFIG_AP)

static int i802_get_seqnum(const char *iface, void *priv, const u8 *addr,
			   int idx, u8 *seq)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int buf_size = 0;
	int ret = 0;
    /* format  seq to buf */
    buf_size = MAX_BUF_LEN;
    ret = wpa_get_seqnum_format(buf, &buf_size, addr, idx, seq);
    if(ret < 0)
    {
        fprintf(stderr,"wpa_get_seqnum_format Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_get_seqnum_format buf_size:%d",buf_size);
    /* send buf(argc) */
    ret = send(agentfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
	return 0;
}


static int i802_set_rts(void *priv, int rts)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
    int buf_size = 0;
    int ret = 0;
	 /* format rts to buf */
	 buf_size = MAX_BUF_LEN;
	 ret = wpa_set_rts_format(buf, &buf_size, rts);
	 if(ret < 0)
	 {
		 fprintf(stderr,"wpa_set_rts_format Error,%s:%d\n",__FILE__,__LINE__);
		 return -1;
	 }
	 wpa_printf(MSG_DEBUG, "nl80211ext: wpa_set_rts_format buf_size:%d",buf_size);
	 /* send buf(freq) */
	 ret = send(agentfd,buf,buf_size,0);
	 if(ret < 0)
	 {
		 fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
		 return -1;
	 }
     return 0;
}


static int i802_set_frag(void *priv, int frag)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int ret;
	int buf_size = MAX_BUF_LEN;
	memset(buf, 0, MAX_BUF_LEN);
	
	ret = wpa_set_frag_format(buf,&buf_size,frag);
	
	if(ret < 0 || buf_size <= 0)
	{
		fprintf(stderr,"wiflow_pdu_format Error,%s:%d\n",__FILE__,__LINE__);  
	    goto err;
	}
	
	ret = send(agentfd,buf,buf_size,0);
	
	if(ret < 0)
	{
		fprintf(stderr,"send Error,%s:%d\n",__FILE__,__LINE__);  
		goto err;
	}
	return 0;

	
err:
	return -1;
}


static int i802_flush(void *priv)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int buf_size = 0;
	int ret = 0;
    /* format  func argc to buf */
    buf_size = MAX_BUF_LEN;
    ret = i802_flush_format(buf, &buf_size);
    if(ret < 0)
    {
        fprintf(stderr,"i802_flush_format Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
    wpa_printf(MSG_DEBUG, "nl80211ext: i802_flush_format buf_size:%d",buf_size);
    /* send buf(argc) */
    ret = send(agentfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
	return 0;
}

#endif /* HOSTAPD || CONFIG_AP */

static int i802_read_sta_data(void *priv, struct hostap_sta_driver_data *data,
			      const u8 *addr)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int buf_size = 0;
	int ret = 0;
    /* format  data argc to buf */
    buf_size = MAX_BUF_LEN;
    ret = wpa_read_sta_data_format(buf, &buf_size, data, addr);
    if(ret < 0)
    {
        fprintf(stderr,"wpa_read_sta_data_format Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_read_sta_data_format buf_size:%d",buf_size);
    /* send buf(data) */
    ret = send(agentfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
	return 0;
}

static int i802_set_tx_queue_params(void *priv, int queue, int aifs,
				    int cw_min, int cw_max, int burst_time)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int buf_size = 0;
	int ret = 0;
    /* format  func argc to buf */
    buf_size = MAX_BUF_LEN;
    ret = wpa_set_tx_queue_params_format(buf, &buf_size, queue, aifs, cw_min, cw_max, burst_time);
    if(ret < 0)
    {
        fprintf(stderr,"wpa_set_tx_queue_params_format Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_set_tx_queue_params_format buf_size:%d",buf_size);
    /* send buf(argc) */
    ret = send(agentfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
	return 0;
}


static int i802_set_sta_vlan(void *priv, const u8 *addr,
			     const char *ifname, int vlan_id)
{
	wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int buf_size = 0;
	int ret = 0;
	/* format  func argc to buf */
	buf_size = MAX_BUF_LEN;
	ret = wpa_set_sta_vlan_format(buf, &buf_size, addr, vlan_id);
	if(ret < 0)
	{
		fprintf(stderr,"wpa_set_sta_vlan_format Error,%s:%d\n",__FILE__,__LINE__);
		return -1;
	}
	wpa_printf(MSG_DEBUG, "nl80211ext: wpa_set_sta_vlan_format buf_size:%d",buf_size);
	/* send buf(argc) */
	ret = send(agentfd,buf,buf_size,0);
	if(ret < 0)
	{
		fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
		return -1;
	}
	return 0;
}


static int i802_get_inact_sec(void *priv, const u8 *addr)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int buf_size = 0;
	int ret = 0;
    /* format  func argc to buf */
    buf_size = MAX_BUF_LEN;
    ret = wpa_get_inact_sec_format(buf, &buf_size, addr);
    if(ret < 0)
    {
        fprintf(stderr,"wpa_get_inact_sec_format Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_get_inact_sec_format buf_size:%d",buf_size);
    /* send buf(argc) */
    ret = send(agentfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
	return 1000;
}


static int i802_sta_clear_stats(void *priv, const u8 *addr)
{
#if 0
	/* TODO */
#endif
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return 0;
}


static int i802_sta_deauth(void *priv, const u8 *own_addr, const u8 *addr,
			   int reason)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int buf_size = 0;
	int ret = 0;
    /* format  argc to buf */
    buf_size = MAX_BUF_LEN;
    ret = wpa_sta_deauth_format(buf, &buf_size, addr, reason);
    if(ret < 0)
    {
        fprintf(stderr,"wpa_sta_deauth_format Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_sta_deauth_format buf_size:%d",buf_size);
    /* send buf(argc) */
    ret = send(agentfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
	return 0;
}


static int i802_sta_disassoc(void *priv, const u8 *own_addr, const u8 *addr,
			     int reason)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int buf_size = 0;
	int ret = 0;
    /* format  argc to buf */
    buf_size = MAX_BUF_LEN;
    ret = wpa_sta_disassoc_format(buf, &buf_size, addr, reason);
    if(ret < 0)
    {
        fprintf(stderr,"wpa_sta_disassoc_format Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_sta_disassoc_format buf_size:%d",buf_size);
    /* send buf(argc) */
    ret = send(agentfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
	return 0;
}

static int i802_set_wds_sta(void *priv, const u8 *addr, int aid, int val,
                            const char *bridge_ifname)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int buf_size = 0;
	int ret = 0;
    /* format  argc to buf */
    buf_size = MAX_BUF_LEN;
    ret = wpa_i802_set_wds_sta_format(buf, &buf_size, addr, aid, val, bridge_ifname);
    if(ret < 0)
    {
        fprintf(stderr,"wpa_i802_set_wds_sta_format Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_i802_set_wds_sta_format buf_size:%d",buf_size);
    /* send buf(mgmt) */
    ret = send(agentfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
	return 0;
}

static int wpa_driver_nl80211_if_add(void *priv, enum wpa_driver_if_type type,
				     const char *ifname, const u8 *addr,
				     void *bss_ctx, void **drv_priv,
				     char *force_ifname, u8 *if_addr,
				     const char *bridge)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int buf_size = 0;
	int ret = 0;
    /* format  argc to buf */
    buf_size = MAX_BUF_LEN;
    ret = wpa_if_add_format(buf, &buf_size, type, ifname, addr, bss_ctx, drv_priv, force_ifname, if_addr);
    if(ret < 0)
    {
        fprintf(stderr,"wpa_if_add_format Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_if_add_format buf_size:%d",buf_size);
    /* send buf(argc) */
    ret = send(agentfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
	return 0;
}


static int wpa_driver_nl80211_if_remove(void *priv,
					enum wpa_driver_if_type type,
					const char *ifname)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
 	int ret;
	int buf_size = MAX_BUF_LEN;
	memset(buf, 0, MAX_BUF_LEN);
	
	ret = wpa_if_remove_format(buf,&buf_size,type,ifname);
	
	if(ret < 0 || buf_size <= 0)
	{
		fprintf(stderr,"wpa_if_remove Error,%s:%d\n",__FILE__,__LINE__);  
	    goto err;
	}
	
	ret = send(agentfd,buf,buf_size,0);
	
	if(ret < 0)
	{
		fprintf(stderr,"send Error,%s:%d\n",__FILE__,__LINE__);  
		goto err;
	}

	return 0;	
err:
	return -1;
}

static int wpa_driver_nl80211_send_action(void *priv, unsigned int freq,
					  unsigned int wait_time,
					  const u8 *dst, const u8 *src,
					  const u8 *bssid,
					  const u8 *data, size_t data_len,
					  int no_cck)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int buf_size = 0;
	int ret = 0;
    /* format  argc to buf */
    buf_size = MAX_BUF_LEN;
    ret = wpa_send_action_format(buf, &buf_size, freq, wait_time, dst, data, data_len);
    if(ret < 0)
    {
        fprintf(stderr,"wpa_if_add_format Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_if_add_format buf_size:%d",buf_size);
    /* send buf(argc) */
    ret = send(agentfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
	return 0;
}


static void wpa_driver_nl80211_send_action_cancel_wait(void *priv)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
}


static int wpa_driver_nl80211_remain_on_channel(void *priv, unsigned int freq,
						unsigned int duration)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return 0;
}


static int wpa_driver_nl80211_cancel_remain_on_channel(void *priv)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return 0;
}


static int wpa_driver_nl80211_probe_req_report(void *priv, int report)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return 0;
}

static int wpa_driver_nl80211_deinit_ap(void *priv)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return 0;
}


static int wpa_driver_nl80211_deinit_p2p_cli(void *priv)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return 0;
}


static void wpa_driver_nl80211_resume(void *priv)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
}


static int nl80211_send_ft_action(void *priv, u8 action, const u8 *target_ap,
				  const u8 *ies, size_t ies_len)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return 0;
}


static int nl80211_signal_monitor(void *priv, int threshold, int hysteresis)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return 0;
}


static int nl80211_signal_poll(void *priv, struct wpa_signal_info *si)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return 0;
}


static int wpa_driver_nl80211_shared_freq(void *priv)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return 1000;
}


static int nl80211_send_frame(void *priv, const u8 *data, size_t data_len,
			      int encrypt)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int buf_size = 0;
	int ret = 0;
    /* format  mgmt to buf */
    buf_size = MAX_BUF_LEN;
    ret = wpa_ieee80211_mgmt_format(buf, &buf_size, data, data_len, encrypt);
    if(ret < 0)
    {
        fprintf(stderr,"wpa_ieee80211_mgmt_format Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_ieee80211_mgmt_format buf_size:%d",buf_size);
    /* send buf(mgmt) */
    ret = send(agentfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
	return 0;
}


static int nl80211_set_param(void *priv, const char *param)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return 0;
}

static const char * nl80211_get_radio_name(void *priv)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return "wlan0";
}

static int nl80211_add_pmkid(void *priv, const u8 *bssid, const u8 *pmkid)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return 0;
}


static int nl80211_remove_pmkid(void *priv, const u8 *bssid, const u8 *pmkid)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return 0;
}


static int nl80211_flush_pmkid(void *priv)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return 0;
}


static void nl80211_set_rekey_info(void *priv, const u8 *kek, const u8 *kck,
				   const u8 *replay_ctr)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
}

static void nl80211_poll_client(void *priv, const u8 *own_addr, const u8 *addr,
				int qos)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int buf_size = 0;
	int ret = 0;
    /* format  argc to buf */
    buf_size = MAX_BUF_LEN;
    ret = wpa_poll_client_format(buf, &buf_size, addr, qos);
    if(ret < 0)
    {
        fprintf(stderr,"wpa_poll_client_format Error,%s:%d\n",__FILE__,__LINE__);
    }
    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_poll_client_format buf_size:%d",buf_size);
    /* send buf(argc) */
    ret = send(agentfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
    }
}

static int nl80211_set_p2p_powersave(void *priv, int legacy_ps, int opp_ps,
				     int ctwindow)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	return 0;
}

/**
 * wpa_driver_nl80211_get_scan_results - Fetch the latest scan results
 * @priv: Pointer to private wext data from wpa_driver_nl80211_init()
 * Returns: Scan results on success, -1 on failure
 */
static struct wpa_scan_results *
wpa_driver_nl80211_get_scan_results(void *priv)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int buf_size = 0;
	int ret = 0;
    /* format  type to buf */
    buf_size = MAX_BUF_LEN;
    ret = wiflow_pdu_format(buf, &buf_size, WIFLOW_NL80211_GET_SCAN_RESULTS2_REQUEST);
    if(ret < 0)
    {
        fprintf(stderr,"wiflow_pdu_format Error,%s:%d\n",__FILE__,__LINE__);
        return NULL;
    }
    wpa_printf(MSG_DEBUG, "nl80211ext: wiflow_pdu_format buf_size:%d",buf_size);
    /* send buf */
    ret = send(agentfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
        return NULL;
    }
	struct wpa_scan_results *res;
	res = os_zalloc(sizeof(*res));
	if (res == NULL)
		return NULL;
	return res;
}
static void  (*init_agent_callback)(void);

static void wpa_driver_nl80211_event_receive(int sock, void *eloop_ctx,
					     void *handle)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
    /* read nl80211 event from agent  */
	struct wpa_driver_capa capa;
	extern struct hapd_interfaces interfaces; 
	union wpa_event_data data;
	enum wpa_event_type event;
//	struct hostapd_iface *iface = (struct hostapd_iface *)eloop_ctx;
	int buf_size = 0;
	int ret;
	buf_size = MAX_BUF_LEN;
	static int count = 0;
    ret = recv(sock,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"Recv Error,%s:%d\n",__FILE__,__LINE__);
        return;
    }
    struct wiflow_pdu *pdu = (struct wiflow_pdu*) buf;
	printf("pdu->type=%d\n",pdu->type);
 	switch (pdu->type) 
 	{
	case WIFLOW_INIT_PARAMS_REQUEST:
	if(count==0)
        init_agent_callback(); /* call init_agent in remoteapd/main.c,why can?*/
	count++;        
	break;
    /* add new case here */
	case WIFLOW_INIT_CAPA_RESPONSE:
		ret = wpa_init_capa_parser(buf,buf_size,&capa);
		interfaces.iface[0]->drv_flags = capa.flags;
		interfaces.iface[0]->probe_resp_offloads = capa.probe_resp_offloads;
		break;
	case REMOTE_HW_MODE:
		ret = remote_hw_modes_parser(buf, buf_size, NULL);
		if(ret < 0)
    	{
        	fprintf(stderr,"Recv Error,%s:%d\n",__FILE__,__LINE__);
    	}
		break;
	case WPA_SUP_EVENT:
		ret = wpa_supplicant_data_parser(buf, buf_size, &data, &event);
		if(ret < 0)
    	{
        	fprintf(stderr,"Recv Error,%s:%d\n",__FILE__,__LINE__);
    	}
		wpa_printf(MSG_DEBUG, "call wpa_supplicant_event");
		wpa_supplicant_event((void*)(ghapd), event, &data);
		break;
	default:
		fprintf(stderr,"Unknown WiFlow PDU type,%s:%d\n",__FILE__,__LINE__);
		return;
	}  
}

static void handle_remote_accept(int sock, void *eloop_ctx, void *sock_ctx)
{
    socklen_t clientaddr_len = sizeof(struct sockaddr);
    struct sockaddr_in clientaddr;
	agentfd = accept(sock,(struct sockaddr *)&clientaddr,&clientaddr_len);
    if(agentfd == -1)
    {
        fprintf(stderr,"Accept Error,%s:%d\n",__FILE__,__LINE__);
        return ;
    }
    if (eloop_register_read_sock(agentfd, wpa_driver_nl80211_event_receive, NULL, NULL)) 
    {
		printf("Could not register remote read socket\n");
		return ;
	}
}

static void *i802_init(struct hostapd_data *hapd,
		       struct wpa_init_params *params)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	ghapd = hapd;
	struct i802_bss *bss = &gbss;
	int buf_size = 0;
	int ret = 0;
    /* format  params to buf */
    buf_size = MAX_BUF_LEN;
    ret = wpa_init_params_format(buf,&buf_size,params);
    if(ret < 0)
    {
        fprintf(stderr,"wpa_init_params_format Error,%s:%d\n",__FILE__,__LINE__);
        return NULL;
    }
    wpa_printf(MSG_DEBUG, "nl80211ext: wpa_init_params_format buf_size:%d",buf_size);
    /* send buf(params) */
    ret = send(agentfd,buf,buf_size,0);
    if(ret < 0)
    {
        fprintf(stderr,"Send Error,%s:%d\n",__FILE__,__LINE__);
        return NULL;
    }
	return bss;
}

static void i802_deinit(void *priv)
{	
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	int buf_size = 0;
	int ret = 0;
    /* format  type to buf */
    buf_size = MAX_BUF_LEN;
    ret = wiflow_pdu_format(buf,&buf_size,WIFLOW_NL80211_HAPD_DEINIT_REQUEST);
	if(ret < 0 || buf_size <= 0)
    {
        fprintf(stderr,"wiflow_pdu_format Error,%s:%d\n",__FILE__,__LINE__);  
    }
	ret = send(agentfd,buf,buf_size,0);
	if(ret < 0)
    {
        fprintf(stderr,"send Error,%s:%d\n",__FILE__,__LINE__);  
    }
}

static void * nl80211_global_init(void)
{
	struct nl80211_global *global;
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	global = os_zalloc(sizeof(*global));
	if (global == NULL)
		return NULL;

	return global;
}

static void nl80211_global_deinit(void *priv)
{
    wpa_printf(MSG_DEBUG, "nl80211ext: %s",__FUNCTION__ );
	struct nl80211_global *global = priv;
	os_free(global);
	close(accept_fd);
}
void  nl80211_agent_init(void (*init)(void))
{
    init_agent_callback = init;
    wpa_printf(MSG_DEBUG, "nl80211ext: %s ...",__FUNCTION__ );
    int ret = -1;
    struct sockaddr_in serveradd;
    serveradd.sin_family = AF_INET;
    serveradd.sin_port = ntohs(PORT);
    serveradd.sin_addr.s_addr = inet_addr(IP_ADDR);
    bzero(&(serveradd.sin_zero),8);
    accept_fd = socket(PF_INET,SOCK_STREAM,0);
    assert(accept_fd != -1);
    ret = bind(accept_fd,(struct sockaddr *)&serveradd,sizeof(struct sockaddr));
    if(ret == -1)
    {
        fprintf(stderr,"Bind Error %s:%d\n",__FILE__,__LINE__);
        return ;
    }
    listen(accept_fd,MAX_CONNECT_QUEUE);

    if (eloop_register_read_sock(accept_fd, handle_remote_accept, NULL, NULL)) 
    {
		printf("Could not register remote accept socket\n");
		return ;
	}
	wpa_printf(MSG_DEBUG, "nl80211ext: %s end",__FUNCTION__ );
	return;
}

const struct wpa_driver_ops wpa_driver_nl80211ext_ops = {
	.name = "nl80211ext",
	.desc = "Linux nl80211/cfg80211",
	.get_bssid = wpa_driver_nl80211_get_bssid,
	.get_ssid = wpa_driver_nl80211_get_ssid,
	.set_key = wpa_driver_nl80211_set_key,
	.scan2 = wpa_driver_nl80211_scan,
	.sched_scan = wpa_driver_nl80211_sched_scan,
	.stop_sched_scan = wpa_driver_nl80211_stop_sched_scan,
	.get_scan_results2 = wpa_driver_nl80211_get_scan_results,
	.deauthenticate = wpa_driver_nl80211_deauthenticate,
	.authenticate = wpa_driver_nl80211_authenticate,
	.associate = wpa_driver_nl80211_associate,
	.global_init = nl80211_global_init,
	.agent_init = nl80211_agent_init,
	.global_deinit = nl80211_global_deinit,
	.init2 = wpa_driver_nl80211_init,
	.deinit = wpa_driver_nl80211_deinit,
	.get_capa = wpa_driver_nl80211_get_capa,
	.set_operstate = wpa_driver_nl80211_set_operstate,
	.set_supp_port = wpa_driver_nl80211_set_supp_port,
	.set_country = wpa_driver_nl80211_set_country,
	.set_ap = wpa_driver_nl80211_set_ap,
	.if_add = wpa_driver_nl80211_if_add,
	.if_remove = wpa_driver_nl80211_if_remove,
	.send_mlme = wpa_driver_nl80211_send_mlme,
	.get_hw_feature_data = wpa_driver_nl80211_get_hw_feature_data,
	.sta_add = wpa_driver_nl80211_sta_add,
	.sta_remove = wpa_driver_nl80211_sta_remove,
	.hapd_send_eapol = wpa_driver_nl80211_hapd_send_eapol,
	.sta_set_flags = wpa_driver_nl80211_sta_set_flags,
#ifdef HOSTAPD
	.hapd_init = i802_init,
	.hapd_deinit = i802_deinit,
	.set_wds_sta = i802_set_wds_sta,
#endif /* HOSTAPD */
#if defined(HOSTAPD) || defined(CONFIG_AP)
	.get_seqnum = i802_get_seqnum,
	.flush = i802_flush,
	.get_inact_sec = i802_get_inact_sec,
	.sta_clear_stats = i802_sta_clear_stats,
	.set_rts = i802_set_rts,
	.set_frag = i802_set_frag,
	.set_tx_queue_params = i802_set_tx_queue_params,
	.set_sta_vlan = i802_set_sta_vlan,
	.sta_deauth = i802_sta_deauth,
	.sta_disassoc = i802_sta_disassoc,
#endif /* HOSTAPD || CONFIG_AP */
	.read_sta_data = i802_read_sta_data,
	.set_freq = i802_set_freq,
	.send_action = wpa_driver_nl80211_send_action,
	.send_action_cancel_wait = wpa_driver_nl80211_send_action_cancel_wait,
	.remain_on_channel = wpa_driver_nl80211_remain_on_channel,
	.cancel_remain_on_channel =
	wpa_driver_nl80211_cancel_remain_on_channel,
	.probe_req_report = wpa_driver_nl80211_probe_req_report,
	.deinit_ap = wpa_driver_nl80211_deinit_ap,
	.deinit_p2p_cli = wpa_driver_nl80211_deinit_p2p_cli,
	.resume = wpa_driver_nl80211_resume,
	.send_ft_action = nl80211_send_ft_action,
	.signal_monitor = nl80211_signal_monitor,
	.signal_poll = nl80211_signal_poll,
	.send_frame = nl80211_send_frame,
	.shared_freq = wpa_driver_nl80211_shared_freq,
	.set_param = nl80211_set_param,
	.get_radio_name = nl80211_get_radio_name,
	.add_pmkid = nl80211_add_pmkid,
	.remove_pmkid = nl80211_remove_pmkid,
	.flush_pmkid = nl80211_flush_pmkid,
	.set_rekey_info = nl80211_set_rekey_info,
	.poll_client = nl80211_poll_client,
	.set_p2p_powersave = nl80211_set_p2p_powersave,
#ifdef CONFIG_TDLS
	.send_tdls_mgmt = nl80211_send_tdls_mgmt,
	.tdls_oper = nl80211_tdls_oper,
#endif /* CONFIG_TDLS */
};
