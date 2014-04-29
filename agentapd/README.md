cloudap
=======

AP Manager in Cloud,AP Hardware on your side.

### agentapd

Based on driver_nl80211.c and the related,AP Hardware on your side.

* cloudap/agentapd$ source build.env (如果出错需要执行dos2unix build.env)
* cloudap/agentapd$ make
* cloudap/agentapd$ sudo ./test (独立模拟启动)
* cloudap/agentapd$ sudo ./agentapd （需要先启动remoteapd/hostapd）


### Driver capability information

struct wpa_driver_capa {

    /* WPA/WPA2/WPA_PSK/WPA2_PSK/WPA_NONE/FT/FT_PSK/WAPI_PSK */
	unsigned int key_mgmt;

    /* WEP40/WEP104/TKIP/CCMP/WEP128/GCMP */
	unsigned int enc;

    /* OPEN/SHARED/LEAP */
	unsigned int auth;

    /* Very many values,ex:supports AP mode etc. */
	unsigned int flags;

	int max_scan_ssids;
	int max_sched_scan_ssids;
	int sched_scan_supported;
	int max_match_sets;

	/* Maximum remain-on-channel duration in msec */
	unsigned int max_remain_on_chan;

	/* max_stations in AP mode */
	unsigned int max_stations;

	/* supported protocols Probe Response offloading. */
	/* WPS/WPS2/P2P/IEEE 802.11u (Interworking) */
	unsigned int probe_resp_offloads;
};

### Supported hardware mode information

struct hostapd_hw_modes {
	/**
	 * mode - Hardware mode
	 */
	enum hostapd_hw_mode mode;

	/**
	 * num_channels - Number of entries in the channels array
	 */
	int num_channels;

	/**
	 * channels - Array of supported channels
	 */
	struct hostapd_channel_data *channels;

	/**
	 * num_rates - Number of entries in the rates array
	 */
	int num_rates;

	/**
	 * rates - Array of supported rates in 100 kbps units
	 */
	int *rates;

	/**
	 * ht_capab - HT (IEEE 802.11n) capabilities
	 */
	u16 ht_capab;

	/**
	 * mcs_set - MCS (IEEE 802.11n) rate parameters
	 */
	u8 mcs_set[16];

	/**
	 * a_mpdu_params - A-MPDU (IEEE 802.11n) parameters
	 */
	u8 a_mpdu_params;

	/**
	 * vht_capab - VHT (IEEE 802.11ac) capabilities
	 */
	u32 vht_capab;

	/**
	 * vht_mcs_set - VHT MCS (IEEE 802.11ac) rate parameters
	 */
	u8 vht_mcs_set[8];

	unsigned int flags; /* HOSTAPD_MODE_FLAG_* */
};
