# IP2Proxy Erlang Module

This module allows user to query an IP address if it was being used as VPN anonymizer, open proxies, web proxies, Tor exits, data center, web hosting (DCH) range and search engine robots (SES). It lookup the proxy IP address from **IP2Proxy BIN Data** file. This data file can be downloaded at

* Free IP2Proxy BIN Data: https://lite.ip2location.com
* Commercial IP2Proxy BIN Data: https://www.ip2location.com/database/ip2proxy


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
|getpackageversion|Get the package version (1 to 8 for PX1 to PX8 respectively).|
|getmoduleversion|Get the module version.|
|getdatabaseversion|Get the database version.|
|isproxy|Check whether if an IP address was a proxy. Returned value:<ul><li>-1 : errors</li><li>0 : not a proxy</li><li>1 : a proxy</li><li>2 : a data center IP address or search engine robot</li></ul>|
|getall|Return the proxy information in an array.|
|getproxytype|Return the proxy type. Please visit <a href="https://www.ip2location.com/database/px8-ip-proxytype-country-region-city-isp-domain-usagetype-asn-lastseen" target="_blank">IP2Location</a> for the list of proxy types supported.|
|getcountryshort|Return the ISO3166-1 country code (2-digits) of the proxy.|
|getcountrylong|Return the ISO3166-1 country name of the proxy.|
|getregion|Return the ISO3166-2 region name of the proxy. Please visit <a href="https://www.ip2location.com/free/iso3166-2" target="_blank">ISO3166-2 Subdivision Code</a> for the information of ISO3166-2 supported.|
|getcity|Return the city name of the proxy.|
|getisp|Return the ISP name of the proxy.|
|getdomain|Return the domain name of the proxy.|
|getusagetype|Return the usage type classification of the proxy. Please visit <a href="https://www.ip2location.com/database/px8-ip-proxytype-country-region-city-isp-domain-usagetype-asn-lastseen" target="_blank">IP2Location</a> for the list of usage types supported.|
|getasn|Return the autonomous system number of the proxy.|
|getas|Return the autonomous system name of the proxy.|
|getlastseen|Return the number of days that the proxy was last seen.|

## Example

```erlang
test:testme().
```
