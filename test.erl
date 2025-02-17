-module(test).
-export([testme/0, testme2/0]).

printme(V) ->
	case V of
		{} ->
			io:format("No results.~n", []);
		{ip2proxyrecord, Country_short, Country_long, Region, City, Isp, Proxy_type, Domain, Usage_type, Asn, As, Last_seen, Threat, Provider, Fraud_score, Is_proxy} ->
			io:format("Country_short: ~p~n", [Country_short]),
			io:format("Country_long: ~p~n", [Country_long]),
			io:format("Region: ~p~n", [Region]),
			io:format("City: ~p~n", [City]),
			io:format("Isp: ~p~n", [Isp]),
			io:format("Proxy_type: ~p~n", [Proxy_type]),
			io:format("Domain: ~p~n", [Domain]),
			io:format("Usage_type: ~p~n", [Usage_type]),
			io:format("Asn: ~p~n", [Asn]),
			io:format("As: ~p~n", [As]),
			io:format("Last_seen: ~p~n", [Last_seen]),
			io:format("Threat: ~p~n", [Threat]),
			io:format("Provider: ~p~n", [Provider]),
			io:format("Fraud_score: ~p~n", [Fraud_score]),
			io:format("Is_proxy: ~p~n", [Is_proxy])
	end,
	io:format("===================================================================~n", []).

testme() ->
	X = "37.252.228.50",
	case ip2proxy:open("./ip2proxy-testdata/IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP-DOMAIN-USAGETYPE-ASN-LASTSEEN-THREAT-RESIDENTIAL-PROVIDER-FRAUDSCORE.BIN") of
	0 ->
		io:format("getpackageversion: ~p~n", [ip2proxy:getpackageversion()]),
		io:format("getmoduleversion: ~p~n", [ip2proxy:getmoduleversion()]),
		io:format("getdatabaseversion: ~p~n", [ip2proxy:getdatabaseversion()]),
		V1 = ip2proxy:getall(X),
		printme(V1),
		
		io:format("Country_short: ~p~n", [ip2proxy:getcountryshort(X)]),
		io:format("Country_long: ~p~n", [ip2proxy:getcountrylong(X)]),
		io:format("Region: ~p~n", [ip2proxy:getregion(X)]),
		io:format("City: ~p~n", [ip2proxy:getcity(X)]),
		io:format("Isp: ~p~n", [ip2proxy:getisp(X)]),
		io:format("Proxy_type: ~p~n", [ip2proxy:getproxytype(X)]),
		io:format("Domain: ~p~n", [ip2proxy:getdomain(X)]),
		io:format("Usage_type: ~p~n", [ip2proxy:getusagetype(X)]),
		io:format("Asn: ~p~n", [ip2proxy:getasn(X)]),
		io:format("AS: ~p~n", [ip2proxy:getas(X)]),
		io:format("Last_seen: ~p~n", [ip2proxy:getlastseen(X)]),
		io:format("Threat: ~p~n", [ip2proxy:getthreat(X)]),
		io:format("Provider: ~p~n", [ip2proxy:getprovider(X)]),
		io:format("Fraud_score: ~p~n", [ip2proxy:getfraudscore(X)]),
		io:format("Is_proxy: ~p~n", [ip2proxy:isproxy(X)]);
	_ ->
		io:format("Error reading BIN file~n", [])
	end,
	
	case ip2proxy:close() of
	-1 ->
		io:format("Error occurred~n", []);
	_ ->
		ok
	end.

testme2() ->
	APIKey = "YOUR_API_KEY",
	APIPackage = "PX11",
	UseSSL = true,
	IP = "37.252.228.50",
	
	ip2proxy:openws(APIKey, APIPackage, UseSSL),
	Result = ip2proxy:lookup(IP),
	case Result of
		{ip2proxyresult, Response, CountryShort, CountryLong, RegionName, CityName, ISP, ProxyType, Domain, UsageType, ASN, AS, LastSeen, Threat, Provider, IsProxy} ->
			case Response of
				"OK" ->
					io:format("CountryShort: ~p~n", [CountryShort]),
					io:format("CountryLong: ~p~n", [CountryLong]),
					io:format("RegionName: ~p~n", [RegionName]),
					io:format("CityName: ~p~n", [CityName]),
					io:format("ISP: ~p~n", [ISP]),
					io:format("ProxyType: ~p~n", [ProxyType]),
					io:format("Domain: ~p~n", [Domain]),
					io:format("UsageType: ~p~n", [UsageType]),
					io:format("ASN: ~p~n", [ASN]),
					io:format("AS: ~p~n", [AS]),
					io:format("LastSeen: ~p~n", [LastSeen]),
					io:format("Threat: ~p~n", [Threat]),
					io:format("Provider: ~p~n", [Provider]),
					io:format("IsProxy: ~p~n", [IsProxy]);
				_ ->
					io:format("Error: ~p~n", [Response])
			end;
		{error, Reason} ->
			io:format("Error: ~p~n", [Reason])
	end,
	
	Credits = ip2proxy:getcredit(),
	io:format("Credit Balance: ~p~n", [Credits]).
