cloudap
=======

AP Manager in Cloud,AP Hardware on your side.

### remoteapd

Based on hostapd 2.0,AP Manager in Cloud

* cloudap/remoteapd$ make
* cloudap/remoteapd$ sudo ./hostapd hostapd.conf (配置文件中使用的driver是nl80211ext哦,wlanX要设定正确的X,如果hostapd.conf文件格式错误请使用dos2unix转换一下)

### agentapd

Based on driver_nl80211.c and the related,AP Hardware on your side.

* cloudap/agentapd$ source build.env (如果出错需要执行dos2unix build.env)
* cloudap/agentapd$ make
* cloudap/agentapd$ ./test (独立模拟启动)
* cloudap/agentapd$ ./agentapd （需要先启动remoteapd/hostapd）


