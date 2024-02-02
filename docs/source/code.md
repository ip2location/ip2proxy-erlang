# IP2Proxy Erlang API

## ip2proxy Class
```{py:function} open(InputFile)
Load the IP2Proxy BIN database for lookup.

:param String InputFile: (Required) The file path links to IP2Proxy BIN databases.
```

```{py:function} getpackageversion()
Return the database's type, 1 to 10 respectively for PX1 to PX11. Please visit https://www.ip2location.com/databases/ip2proxy for details.

:return: Returns the package version.
:rtype: String
```

```{py:function} getmoduleversion()
Return the version of module.

:return: Returns the module version.
:rtype: String
```

```{py:function} getdatabaseversion()
Return the database's compilation date as a string of the form 'YYYY-MM-DD'.

:return: Returns the database version.
:rtype: String
```

```{py:function} close()
Closes BIN file and resets metadata.
```

```{py:function} getall(Ip)
Retrieve geolocation information for an IP address.

:param String Ip: (Required) The IP address (IPv4 or IPv6).
:return: Returns the geolocation information in array. Refer below table for the fields avaliable in the array
:rtype: Record

**RETURN FIELDS**

| Field Name       | Description                                                  |
| ---------------- | ------------------------------------------------------------ |
| Country_short    |     Two-character country code based on ISO 3166. |
| Country_long    |     Country name based on ISO 3166. |
| Region     |     Region or state name. |
| City       |     City name. |
| ISP            |     Internet Service Provider or company\'s name. |
| Domain         |     Internet domain name associated with IP address range. |
| Usage_type      |     Usage type classification of ISP or company. |
| ASN            |     Autonomous system number (ASN). |
| AS             |     Autonomous system (AS) name. |
| Last_seen       |     Proxy last seen in days. |
| Threat         |     Security threat reported. |
| Provider       |     Name of VPN provider if available. |
```