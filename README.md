# IP2Proxy Erlang Module

This module allows user to query an IP address if it was being used as VPN anonymizer, open proxies, web proxies, Tor exits, data center, web hosting (DCH) range, search engine robots (SES) and residential (RES). It lookup the proxy IP address from **IP2Proxy BIN Data** file. This data file can be downloaded at

* Free IP2Proxy BIN Data: https://lite.ip2location.com
* Commercial IP2Proxy BIN Data: https://www.ip2location.com/database/ip2proxy

As an alternative, this module can also call the IP2Proxy Web Service. This requires an API key. If you don't have an existing API key, you can subscribe for one at the below:

https://www.ip2location.com/web-service/ip2proxy

## Compilation

```bash
erlc ip2proxy.erl test.erl
```

## QUERY USING THE BIN FILE

## Methods
Below are the methods supported in this package.

|Method Name|Description|
|---|---|
|open|Open the IP2Proxy BIN data for lookup.|
|close|Close and clean up metadata.|
|getpackageversion|Get the package version (1 to 11 for PX1 to PX11 respectively).|
|getmoduleversion|Get the module version.|
|getdatabaseversion|Get the database version.|
|isproxy|Check whether if an IP address was a proxy. Returned value:<ul><li>-1 : errors</li><li>0 : not a proxy</li><li>1 : a proxy</li><li>2 : a data center IP address or search engine robot</li></ul>|
|getall|Return the proxy information in an array.|
|getproxytype|Return the proxy type. Please visit <a href="https://www.ip2location.com/database/px10-ip-proxytype-country-region-city-isp-domain-usagetype-asn-lastseen-threat-residential" target="_blank">IP2Location</a> for the list of proxy types supported.|
|getcountryshort|Return the ISO3166-1 country code (2-digits) of the proxy.|
|getcountrylong|Return the ISO3166-1 country name of the proxy.|
|getregion|Return the ISO3166-2 region name of the proxy. Please visit <a href="https://www.ip2location.com/free/iso3166-2" target="_blank">ISO3166-2 Subdivision Code</a> for the information of ISO3166-2 supported.|
|getcity|Return the city name of the proxy.|
|getisp|Return the ISP name of the proxy.|
|getdomain|Return the domain name of the proxy.|
|getusagetype|Return the usage type classification of the proxy. Please visit <a href="https://www.ip2location.com/database/px10-ip-proxytype-country-region-city-isp-domain-usagetype-asn-lastseen-threat-residential" target="_blank">IP2Location</a> for the list of usage types supported.|
|getasn|Return the autonomous system number of the proxy.|
|getas|Return the autonomous system name of the proxy.|
|getlastseen|Return the number of days that the proxy was last seen.|
|getthreat|Return the threat type of the proxy.|
|getprovider|Return the provider of the proxy.|

## Example

```erlang
test:testme().
```

## QUERY USING THE IP2PROXY PROXY DETECTION WEB SERVICE

## Methods
Below are the methods supported in this package.

|Method Name|Description|
|---|---|
|openws| Expects 3 input parameters:<ol><li>IP2Proxy API Key.</li><li>Package (PX1 - PX11)</li></li><li>Use HTTPS or HTTP</li></ol> |
|lookup|Query IP address. This method returns a map containing the proxy info. <ul><li>countryCode</li><li>countryName</li><li>regionName</li><li>cityName</li><li>isp</li><li>domain</li><li>usageType</li><li>asn</li><li>as</li><li>lastSeen</li><li>threat</li><li>proxyType</li><li>isProxy</li><li>provider</li><ul>|
|getcredit|This method returns the web service credit balance.|

## Usage

```erlang
test:testme2().
```