-module(test).
-export([testme/0]).

printme(V) ->
	case V of
		{} ->
			io:format("No results.~n", []);
		{ip2proxyrecord, Country_short, Country_long, Region, City, Isp, Proxy_type, Domain, Usage_type, Asn, As, Last_seen, Threat, Is_proxy} ->
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
			io:format("Is_proxy: ~p~n", [Is_proxy])
	end,
	io:format("===================================================================~n", []).

testme() ->
	X = "37.252.228.50",
	case ip2proxy:open("./IP2Proxy/bin/IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP-DOMAIN-USAGETYPE-ASN-LASTSEEN-THREAT-RESIDENTIAL.BIN") of
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
