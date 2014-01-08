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

#define PORT                    5001
#define IP_ADDR                 "127.0.0.1"
#define MAX_CONNECT_QUEUE       1024
#define MAX_BUF_LEN             1024

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

struct i802_bss {
	struct wpa_driver_nl80211_data *drv;
	struct i802_bss *next;
	int ifindex;
	char ifname[IFNAMSIZ + 1];
	char brname[IFNAMSIZ];
	unsigned int beacon_set:1;
	unsigned int added_if_into_bridge:1;
	unsigned int added_bridge:1;
	unsigned int in_deinit:1;

	u8 addr[ETH_ALEN];

	int freq;

	void *ctx;
	struct nl_handle *nl_preq, *nl_mgmt;
	struct nl_cb *nl_cb;

	struct nl80211_wiphy_data *wiphy_data;
	struct dl_list wiphy_list;
};

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
	return 0;
}


static int wpa_driver_nl80211_get_ssid(void *priv, u8 *ssid)
{
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

}

/**
 * wpa_driver_nl80211_scan - Request the driver to initiate scan
 * @priv: Pointer to private driver data from wpa_driver_nl80211_init()
 * @params: Scan parameters
 * Returns: 0 on success, -1 on failure
 */
static int wpa_driver_nl80211_scan(void *priv,
				   struct wpa_driver_scan_params *params)
{
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
	return 0;
}


/**
 * wpa_driver_nl80211_stop_sched_scan - Stop a scheduled scan
 * @priv: Pointer to private driver data from wpa_driver_nl80211_init()
 * Returns: 0 on success, -1 on failure or if not supported
 */
static int wpa_driver_nl80211_stop_sched_scan(void *priv)
{

	return 0;
}

static int wpa_driver_nl80211_set_key(const char *ifname, void *priv,
				      enum wpa_alg alg, const u8 *addr,
				      int key_idx, int set_tx,
				      const u8 *seq, size_t seq_len,
				      const u8 *key, size_t key_len)
{

	return 0;
}

static int wpa_driver_nl80211_deauthenticate(void *priv, const u8 *addr,
					     int reason_code)
{

	return 0;
}

static int wpa_driver_nl80211_authenticate(
	void *priv, struct wpa_driver_auth_params *params)
{
	return 0;
}

static struct hostapd_hw_modes *
wpa_driver_nl80211_get_hw_feature_data(void *priv, u16 *num_modes, u16 *flags)
{
	return NULL;
}

static int wpa_driver_nl80211_send_mlme(void *priv, const u8 *data,
					size_t data_len, int noack)
{

	return 0;
}

static int wpa_driver_nl80211_set_ap(void *priv,
				     struct wpa_driver_ap_params *params)
{
	return 0;
}

static int wpa_driver_nl80211_sta_add(void *priv,
				      struct hostapd_sta_add_params *params)
{
	return 0;
}


static int wpa_driver_nl80211_sta_remove(void *priv, const u8 *addr)
{
	return 0;
}


static const u8 rfc1042_header[6] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };

static int wpa_driver_nl80211_hapd_send_eapol(
	void *priv, const u8 *addr, const u8 *data,
	size_t data_len, int encrypt, const u8 *own_addr, u32 flags)
{
	return 0;
}


static int wpa_driver_nl80211_sta_set_flags(void *priv, const u8 *addr,
					    int total_flags,
					    int flags_or, int flags_and)
{
	return 0;
}

static int wpa_driver_nl80211_associate(
	void *priv, struct wpa_driver_associate_params *params)
{

	return 0;
}

static int wpa_driver_nl80211_get_capa(void *priv,
				       struct wpa_driver_capa *capa)
{
	return 0;
}


static int wpa_driver_nl80211_set_operstate(void *priv, int state)
{

	return 0;
}


static int wpa_driver_nl80211_set_supp_port(void *priv, int authorized)
{

	return 0;
}


/* Set kernel driver on given frequency (MHz) */
static int i802_set_freq(void *priv, struct hostapd_freq_params *freq)
{
	return 0;
}


#if defined(HOSTAPD) || defined(CONFIG_AP)

static int i802_get_seqnum(const char *iface, void *priv, const u8 *addr,
			   int idx, u8 *seq)
{
	return 0;
}


static int i802_set_rts(void *priv, int rts)
{
	return 0;
}


static int i802_set_frag(void *priv, int frag)
{
	return 0;
}


static int i802_flush(void *priv)
{
	return 0;
}

#endif /* HOSTAPD || CONFIG_AP */

static int i802_read_sta_data(void *priv, struct hostap_sta_driver_data *data,
			      const u8 *addr)
{
	return 0;
}

static int i802_set_tx_queue_params(void *priv, int queue, int aifs,
				    int cw_min, int cw_max, int burst_time)
{
	return 0;
}


static int i802_set_sta_vlan(void *priv, const u8 *addr,
			     const char *ifname, int vlan_id)
{
	return 0;
}


static int i802_get_inact_sec(void *priv, const u8 *addr)
{
	return 1000;
}


static int i802_sta_clear_stats(void *priv, const u8 *addr)
{
#if 0
	/* TODO */
#endif
	return 0;
}


static int i802_sta_deauth(void *priv, const u8 *own_addr, const u8 *addr,
			   int reason)
{
	return 0;
}


static int i802_sta_disassoc(void *priv, const u8 *own_addr, const u8 *addr,
			     int reason)
{
	return 0;
}

static int i802_set_wds_sta(void *priv, const u8 *addr, int aid, int val,
                            const char *bridge_ifname)
{
	return 0;
}

static void *i802_init(struct hostapd_data *hapd,
		       struct wpa_init_params *params)
{
    struct wpa_driver_nl80211_data *drv;
	struct i802_bss *bss;
	drv = os_zalloc(sizeof(*drv));
	if (drv == NULL)
		return NULL;
	bss = &drv->first_bss;
	return bss;
}


static void i802_deinit(void *priv)
{
}

static int wpa_driver_nl80211_if_add(void *priv, enum wpa_driver_if_type type,
				     const char *ifname, const u8 *addr,
				     void *bss_ctx, void **drv_priv,
				     char *force_ifname, u8 *if_addr,
				     const char *bridge)
{
	return 0;
}


static int wpa_driver_nl80211_if_remove(void *priv,
					enum wpa_driver_if_type type,
					const char *ifname)
{
	return 0;
}

static int wpa_driver_nl80211_send_action(void *priv, unsigned int freq,
					  unsigned int wait_time,
					  const u8 *dst, const u8 *src,
					  const u8 *bssid,
					  const u8 *data, size_t data_len,
					  int no_cck)
{
	return 0;
}


static void wpa_driver_nl80211_send_action_cancel_wait(void *priv)
{
}


static int wpa_driver_nl80211_remain_on_channel(void *priv, unsigned int freq,
						unsigned int duration)
{
	return 0;
}


static int wpa_driver_nl80211_cancel_remain_on_channel(void *priv)
{
	return 0;
}


static int wpa_driver_nl80211_probe_req_report(void *priv, int report)
{
	return 0;
}

static int wpa_driver_nl80211_deinit_ap(void *priv)
{
	return 0;
}


static int wpa_driver_nl80211_deinit_p2p_cli(void *priv)
{
	return 0;
}


static void wpa_driver_nl80211_resume(void *priv)
{
}


static int nl80211_send_ft_action(void *priv, u8 action, const u8 *target_ap,
				  const u8 *ies, size_t ies_len)
{
	return 0;
}


static int nl80211_signal_monitor(void *priv, int threshold, int hysteresis)
{
	return 0;
}


static int nl80211_signal_poll(void *priv, struct wpa_signal_info *si)
{
	return 0;
}


static int wpa_driver_nl80211_shared_freq(void *priv)
{
	return 1000;
}


static int nl80211_send_frame(void *priv, const u8 *data, size_t data_len,
			      int encrypt)
{
	return 0;
}


static int nl80211_set_param(void *priv, const char *param)
{
	return 0;
}

static const char * nl80211_get_radio_name(void *priv)
{
	return "wlan0";
}

static int nl80211_add_pmkid(void *priv, const u8 *bssid, const u8 *pmkid)
{
	return 0;
}


static int nl80211_remove_pmkid(void *priv, const u8 *bssid, const u8 *pmkid)
{
	return 0;
}


static int nl80211_flush_pmkid(void *priv)
{
	return 0;
}


static void nl80211_set_rekey_info(void *priv, const u8 *kek, const u8 *kck,
				   const u8 *replay_ctr)
{
}

static void nl80211_poll_client(void *priv, const u8 *own_addr, const u8 *addr,
				int qos)
{

}

static int nl80211_set_p2p_powersave(void *priv, int legacy_ps, int opp_ps,
				     int ctwindow)
{
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
	struct wpa_scan_results *res;
	res = os_zalloc(sizeof(*res));
	if (res == NULL)
		return NULL;
	return res;
}

static void * nl80211_global_init(void)
{
	struct nl80211_global *global;

	global = os_zalloc(sizeof(*global));
	if (global == NULL)
		return NULL;
	return global;
}

static void nl80211_global_deinit(void *priv)
{
	struct nl80211_global *global = priv;
	os_free(global);
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
