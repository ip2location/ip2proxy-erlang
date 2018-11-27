# IP2Proxy Erlang Module

This module allows user to query an IP address if it was being used as open proxy, web proxy, VPN anonymizer and TOR exits. It lookup the proxy IP address from **IP2Proxy BIN Data** file. This data file can be downloaded at

* Free IP2Proxy BIN Data: http://lite.ip2location.com
* Commercial IP2Proxy BIN Data: http://www.ip2location.com/proxy-database


## Compilation

```bash
erlc ip2proxy.erl test.erl
```

## Methods
Below are the methods supported in this package.

|Method Name|Description|
|---|---|
|open|Open the IP2Proxy BIN data for lookup.|
|close|Close and clean up metadata.|
|getpackageversion|Get the package version (1 to 4 for PX1 to PX4 respectively).|
|getmoduleversion|Get the module version.|
|getdatabaseversion|Get the database version.|
|isproxy|Check whether if an IP address was a proxy. Returned value:<ul><li>-1 : errors</li><li>0 : not a proxy</li><li>1 : a proxy</li><li>2 : a data center IP address</li></ul>|
|getall|Return the proxy information in an array.|
|getproxytype|Return the proxy type. Please visit <a href="https://www.ip2location.com/databases/px4-ip-proxytype-country-region-city-isp" target="_blank">IP2Location</a> for the list of proxy types supported|
|getcountryshort|Return the ISO3166-1 country code (2-digits) of the proxy.|
|getcountrylong|Return the ISO3166-1 country name of the proxy.|
|getregion|Return the ISO3166-2 region name of the proxy. Please visit <a href="https://www.ip2location.com/free/iso3166-2" target="_blank">ISO3166-2 Subdivision Code</a> for the information of ISO3166-2 supported|
|getcity|Return the city name of the proxy.|
|getisp|Return the ISP name of the proxy.|

## Example

```erlang
test:testme().
```