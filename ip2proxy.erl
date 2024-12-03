-module(ip2proxy).
-export([getpackageversion/0, getmoduleversion/0, getdatabaseversion/0, open/1, getall/1, getproxytype/1, getcountryshort/1, getcountrylong/1, getregion/1, getcity/1, getisp/1, getdomain/1, getusagetype/1, getasn/1, getas/1, getlastseen/1, getthreat/1, getprovider/1, isproxy/1, close/0, openws/3, lookup/1, getcredit/0]).
-record(ip2proxyrecord, {
	country_short = "-",
	country_long = "-",
	region = "-",
	city = "-",
	isp = "-",
	proxy_type = "-",
	domain = "-",
	usage_type = "-",
	asn = "-",
	as = "-",
	last_seen = "-",
	threat = "-",
	provider = "-",
	is_proxy = 0
}).
-record(ip2proxyresult, {
	response = "-",
	countryCode = "-",
	countryName = "-",
	regionName = "-",
	cityName = "-",
	isp = "-",
	proxyType = "-",
	domain = "-",
	usageType = "-",
	asn = "-",
	as = "-",
	lastSeen = "-",
	threat = "-",
	provider = "-",
	isProxy = "-"
}).
-define(IF(Cond), (case (Cond) of true -> (0); false -> (1) end)).

getpackageversion() ->
	case ets:info(mymeta) of
		undefined ->
			io:format("Error: Unable to read metadata.~n", []),
			{}; % return empty
		_ ->
			case ets:lookup(mymeta, databasetype) of
				[] ->
					io:format("Error: Unable to read metadata.~n", []),
					{}; % return empty
				[{_, Databasetype}] ->
					Databasetype
				end
	end.

getmoduleversion() ->
	"3.3.3".

getdatabaseversion() ->
	case ets:info(mymeta) of
		undefined ->
			io:format("Error: Unable to read metadata.~n", []),
			{}; % return empty
		_ ->
			case ets:lookup(mymeta, databaseyear) of
				[] ->
					io:format("Error: Unable to read metadata.~n", []),
					{}; % return empty
				[{_, Databaseyear}] ->
					[{_, Databasemonth}] = ets:lookup(mymeta, databasemonth),
					[{_, Databaseday}] = ets:lookup(mymeta, databaseday),
					lists:concat(["20", Databaseyear, ".", Databasemonth, ".", Databaseday])
			end
	end.

readuintrow(R, StartPos, Len) ->
	Data = binary:part(R, StartPos, Len),
	binary:decode_unsigned(Data, little).

readuint8row(R, StartPos) ->
	readuintrow(R, StartPos, 1).

readuint32row(R, StartPos) ->
	readuintrow(R, StartPos, 4).

readuint128row(R, StartPos) ->
	readuintrow(R, StartPos, 16).

readstr(S, StartPos) ->
	case file:pread(S, StartPos, 256) of % max size of string field + 1 byte for the length
	eof ->
		ok;
	{ok, R} ->
		Len = readuint8row(R, 0),
		Data = binary:part(R, 1, Len),
		binary_to_list(Data)
	end.

input(InputFile) ->
	case file:open(InputFile, [read, binary, raw]) of
		{ok, S} ->
			{ok, S};
		{_, _} ->
			-1
	end.

open(InputFile) ->
	case input(InputFile) of
	{ok, S} ->
		case file:pread(S, 0, 64) of % 64-byte header
		eof ->
			halt();
		{ok, Data} ->
			R = Data,
			Databasetype = readuint8row(R, 0),
			Databasecolumn = readuint8row(R, 1),
			Databaseyear = readuint8row(R, 2),
			Databasemonth = readuint8row(R, 3),
			Databaseday = readuint8row(R, 4),
			Ipv4databasecount = readuint32row(R, 5),
			Ipv4databaseaddr = readuint32row(R, 9),
			Ipv6databasecount = readuint32row(R, 13),
			Ipv6databaseaddr = readuint32row(R, 17),
			Ipv4indexbaseaddr = readuint32row(R, 21),
			Ipv6indexbaseaddr = readuint32row(R, 25),
			Productcode = readuint8row(R, 29),
			Ipv4columnsize = Databasecolumn bsl 2, % 4 bytes each column
			Ipv6columnsize = 16 + ((Databasecolumn - 1) bsl 2), % 4 bytes each column, except IPFrom column which is 16 bytes
			% Producttype = readuint8row(R, 30),
			% Filesize = readuint32row(R, 31),
			file:close(S),
			
			if
				% check if is correct BIN (should be 2 for IP2Proxy BIN file), also checking for zipped file (PK being the first 2 chars)
				(Productcode /= 2 andalso Databaseyear >= 21) orelse (Databasetype == 80 andalso Databasecolumn == 75) ->
					io:format("Incorrect IP2Proxy BIN file format. Please make sure that you are using the latest IP2Proxy BIN file.~n", []),
					halt();
				true ->
					case ets:info(mymeta) of
						undefined ->
							ets:new(mymeta, [set, named_table]),
							ets:insert(mymeta, {inputfile, InputFile}),
							ets:insert(mymeta, {databasetype, Databasetype}),
							ets:insert(mymeta, {databasecolumn, Databasecolumn}),
							ets:insert(mymeta, {databaseyear, Databaseyear}),
							ets:insert(mymeta, {databasemonth, Databasemonth}),
							ets:insert(mymeta, {databaseday, Databaseday}),
							ets:insert(mymeta, {ipv4databasecount, Ipv4databasecount}),
							ets:insert(mymeta, {ipv4databaseaddr, Ipv4databaseaddr}),
							ets:insert(mymeta, {ipv6databasecount, Ipv6databasecount}),
							ets:insert(mymeta, {ipv6databaseaddr, Ipv6databaseaddr}),
							ets:insert(mymeta, {ipv4indexbaseaddr, Ipv4indexbaseaddr}),
							ets:insert(mymeta, {ipv6indexbaseaddr, Ipv6indexbaseaddr}),
							ets:insert(mymeta, {ipv4columnsize, Ipv4columnsize}),
							ets:insert(mymeta, {ipv6columnsize, Ipv6columnsize}),
							0; % zero means success
						_ ->
							ok % do nothing
					end
			end
		end;
	_ ->
		-1 % negative one means error
	end.

readcolcountryrow(S, R, Dbtype, Col) ->
	X = "NOT SUPPORTED",
	case lists:nth(Dbtype, Col) of
		0 ->
			{X, X};
		Colpos ->
			Coloffset = (Colpos - 2) bsl 2,
			X0 = readuint32row(R, Coloffset),
			X1 = readstr(S, X0),
			X2 = readstr(S, X0 + 3),
			{X1, X2}
	end.

readcolstringrow(S, R, Dbtype, Col) ->
	case lists:nth(Dbtype, Col) of
		0 ->
			"NOT SUPPORTED";
		Colpos ->
			Coloffset = (Colpos - 2) bsl 2,
			readstr(S, readuint32row(R, Coloffset))
	end.

readrecord(S, R, Dbtype, Mode) ->
	Country_position = [0, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3],
	Region_position = [0, 0, 0, 4, 4, 4, 4, 4, 4, 4, 4, 4],
	City_position = [0, 0, 0, 5, 5, 5, 5, 5, 5, 5, 5, 5],
	Isp_position = [0, 0, 0, 0, 6, 6, 6, 6, 6, 6, 6, 6],
	Proxytype_position = [0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2],
	Domain_position = [0, 0, 0, 0, 0, 7, 7, 7, 7, 7, 7, 7],
	Usagetype_position = [0, 0, 0, 0, 0, 0, 8, 8, 8, 8, 8, 8],
	Asn_position = [0, 0, 0, 0, 0, 0, 0, 9, 9, 9, 9, 9],
	As_position = [0, 0, 0, 0, 0, 0, 0, 10, 10, 10, 10, 10],
	Lastseen_position = [0, 0, 0, 0, 0, 0, 0, 0, 11, 11, 11, 11],
	Threat_position = [0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 12, 12],
	Provider_position = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13],
	
	Countryshort_field = 1,
	Countrylong_field = 2,
	Region_field = 4,
	City_field = 8,
	Isp_field = 16,
	Proxytype_field = 32,
	Isproxy_field = 64,
	Domain_field = 128,
	Usagetype_field = 256,
	Asn_field = 512,
	As_field = 1024,
	Lastseen_field = 2048,
	Threat_field = 4096,
	Provider_field = 8192,
	
	if
		(Mode band Proxytype_field /= 0) or (Mode band Isproxy_field /= 0) ->
			Proxy_type = readcolstringrow(S, R, Dbtype, Proxytype_position);
		true ->
			Proxy_type = ""
	end,
	
	if
		(Mode band Countryshort_field /= 0) or (Mode band Countrylong_field /= 0) or (Mode band Isproxy_field /= 0) ->
			{Country_short, Country_long} = readcolcountryrow(S, R, Dbtype, Country_position);
		true ->
			{Country_short, Country_long} = {"", ""}
	end,
	
	if
		Mode band Region_field /= 0 ->
			Region = readcolstringrow(S, R, Dbtype, Region_position);
		true ->
			Region = ""
	end,
	
	if
		Mode band City_field /= 0 ->
			City = readcolstringrow(S, R, Dbtype, City_position);
		true ->
			City = ""
	end,
	
	if
		Mode band Isp_field /= 0 ->
			Isp = readcolstringrow(S, R, Dbtype, Isp_position);
		true ->
			Isp = ""
	end,
	
	if
		Mode band Domain_field /= 0 ->
			Domain = readcolstringrow(S, R, Dbtype, Domain_position);
		true ->
			Domain = ""
	end,
	
	if
		Mode band Usagetype_field /= 0 ->
			Usage_type = readcolstringrow(S, R, Dbtype, Usagetype_position);
		true ->
			Usage_type = ""
	end,
	
	if
		Mode band Asn_field /= 0 ->
			Asn = readcolstringrow(S, R, Dbtype, Asn_position);
		true ->
			Asn = ""
	end,
	
	if
		Mode band As_field /= 0 ->
			As = readcolstringrow(S, R, Dbtype, As_position);
		true ->
			As = ""
	end,
	
	if
		Mode band Lastseen_field /= 0 ->
			Last_seen = readcolstringrow(S, R, Dbtype, Lastseen_position);
		true ->
			Last_seen = ""
	end,
	
	if
		Mode band Threat_field /= 0 ->
			Threat = readcolstringrow(S, R, Dbtype, Threat_position);
		true ->
			Threat = ""
	end,
	
	if
		Mode band Provider_field /= 0 ->
			Provider = readcolstringrow(S, R, Dbtype, Provider_position);
		true ->
			Provider = ""
	end,
	
	if
		(Country_short == "-") or (Proxy_type == "-") ->
			Is_proxy = 0;
		true ->
			if
				(Proxy_type == "DCH") or (Proxy_type == "SES") ->
					Is_proxy = 2;
				true ->
					Is_proxy = 1
			end
	end,
	
	#ip2proxyrecord{
	country_short = Country_short,
	country_long = Country_long,
	region = Region,
	city = City,
	isp = Isp,
	proxy_type = Proxy_type,
	domain = Domain,
	usage_type = Usage_type,
	asn = Asn,
	as = As,
	last_seen = Last_seen,
	threat = Threat,
	provider = Provider,
	is_proxy = Is_proxy
	}.

searchtree(S, Ipnum, Dbtype, Low, High, BaseAddr, Colsize, Iptype, Mode) ->
	X = "INVALID IP ADDRESS",
	
	if
		Low =< High ->
			Mid = ((Low + High) bsr 1),
			Rowoffset = BaseAddr + (Mid * Colsize),
			
			case Iptype of
			ipv4 ->
				Firstcol = 4; % 4 bytes
			ipv6 ->
				Firstcol = 16 % 16 bytes
			end,
			
			Readlen = Colsize + Firstcol,
			case file:pread(S, Rowoffset - 1, Readlen) of % reading IP From + whole row + next IP From
			eof ->
				io:format("Error: IP address not found.~n", []),
				{}; % return empty
			{ok, R} ->
				if
					Iptype == ipv4 ->
						Ipfrom = readuint32row(R, 0),
						Ipto = readuint32row(R, Colsize);
					true ->
						Ipfrom = readuint128row(R, 0),
						Ipto = readuint128row(R, Colsize)
				end,
				
				if
					Ipnum >= Ipfrom andalso Ipnum < Ipto ->
						Rowlen = Colsize - Firstcol,
						R2 = binary:part(R, Firstcol, Rowlen),
						
						readrecord(S, R2, Dbtype + 1, Mode);
					true ->
						if
							Ipnum < Ipfrom ->
								searchtree(S, Ipnum, Dbtype, Low, Mid - 1, BaseAddr, Colsize, Iptype, Mode);
							true ->
								searchtree(S, Ipnum, Dbtype, Mid + 1, High, BaseAddr, Colsize, Iptype, Mode)
						end
				end
			end;
		true ->
			#ip2proxyrecord{
			country_short = X,
			country_long = X,
			region = X,
			city = X,
			isp = X,
			proxy_type = X,
			domain = X,
			usage_type = X,
			asn = X,
			as = X,
			last_seen = X,
			threat = X,
			provider = X,
			is_proxy = -1
			}
	end.

search4(S, Ipnum, Dbtype, Low, High, Baseaddr, Indexbaseaddr, Colsize, Mode) ->
	if
		Ipnum == 4294967295 ->
			Ipnum2 = Ipnum - 1;
		true ->
			Ipnum2 = Ipnum
	end,
	if
		Indexbaseaddr > 0 ->
			Indexpos = ((Ipnum2 bsr 16) bsl 3) + Indexbaseaddr,
			case file:pread(S, Indexpos - 1, 8) of % 4 bytes for each IP From & IP To
			eof ->
				io:format("Error: IP address not found.~n", []),
				{}; % return empty
			{ok, R} ->
				Low2 = readuint32row(R, 0),
				High2 = readuint32row(R, 4),
				searchtree(S, Ipnum2, Dbtype, Low2, High2, Baseaddr, Colsize, ipv4, Mode)
			end;
		true ->
			searchtree(S, Ipnum2, Dbtype, Low, High, Baseaddr, Colsize, ipv4, Mode)
	end.

search6(S, Ipnum, Dbtype, Low, High, Baseaddr, Indexbaseaddr, Colsize, Mode) ->
	if
		Ipnum == 340282366920938463463374607431768211455 ->
			Ipnum2 = Ipnum - 1;
		true ->
			Ipnum2 = Ipnum
	end,
	if
		Indexbaseaddr > 0 ->
			Indexpos = ((Ipnum2 bsr 112) bsl 3) + Indexbaseaddr,
			case file:pread(S, Indexpos - 1, 8) of % 4 bytes for each IP From & IP To
			eof ->
				io:format("Error: IP address not found.~n", []),
				{}; % return empty
			{ok, R} ->
				Low2 = readuint32row(R, 0),
				High2 = readuint32row(R, 4),
				searchtree(S, Ipnum2, Dbtype, Low2, High2, Baseaddr, Colsize, ipv6, Mode)
			end;
		true ->
			searchtree(S, Ipnum2, Dbtype, Low, High, Baseaddr, Colsize, ipv6, Mode)
	end.

getall(Ip) ->
	query(Ip, 16383).

getcountryshort(Ip) ->
	Result = query(Ip, 1),
	Result#ip2proxyrecord.country_short.

getcountrylong(Ip) ->
	Result = query(Ip, 2),
	Result#ip2proxyrecord.country_long.

getregion(Ip) ->
	Result = query(Ip, 4),
	Result#ip2proxyrecord.region.

getcity(Ip) ->
	Result = query(Ip, 8),
	Result#ip2proxyrecord.city.

getisp(Ip) ->
	Result = query(Ip, 16),
	Result#ip2proxyrecord.isp.

getproxytype(Ip) ->
	Result = query(Ip, 32),
	Result#ip2proxyrecord.proxy_type.

getdomain(Ip) ->
	Result = query(Ip, 128),
	Result#ip2proxyrecord.domain.

getusagetype(Ip) ->
	Result = query(Ip, 256),
	Result#ip2proxyrecord.usage_type.

getasn(Ip) ->
	Result = query(Ip, 512),
	Result#ip2proxyrecord.asn.

getas(Ip) ->
	Result = query(Ip, 1024),
	Result#ip2proxyrecord.as.

getlastseen(Ip) ->
	Result = query(Ip, 2048),
	Result#ip2proxyrecord.last_seen.

getthreat(Ip) ->
	Result = query(Ip, 4096),
	Result#ip2proxyrecord.threat.

getprovider(Ip) ->
	Result = query(Ip, 8192),
	Result#ip2proxyrecord.provider.

isproxy(Ip) ->
	Result = query(Ip, 64),
	Result#ip2proxyrecord.is_proxy.

query(Ip, Mode) ->
	X = "INVALID IP ADDRESS",
	Y = "INVALID BIN FILE",
	Z = "IPV6 MISSING IN IPV4 BIN",
	Fromv4mapped = 281470681743360,
	Tov4mapped = 281474976710655,
	From6to4 = 42545680458834377588178886921629466624,
	To6to4 = 42550872755692912415807417417958686719,
	Fromteredo = 42540488161975842760550356425300246528,
	Toteredo = 42540488241204005274814694018844196863,
	Last32bits = 4294967295,
	
	case ets:info(mymeta) of
		undefined ->
			io:format("Error: Unable to read metadata.~n", []),
			{}; % return empty
		_ ->
			case ets:lookup(mymeta, inputfile) of
				[] ->
					io:format("Error: Unable to read metadata.~n", []),
					{}; % return empty
				[{_, InputFile}] ->
					case input(InputFile) of
						{ok, S} ->
							[{_, Databasetype}] = ets:lookup(mymeta, databasetype),
							% [{_, Databasecolumn}] = ets:lookup(mymeta, databasecolumn),
							% [{_, Databaseyear}] = ets:lookup(mymeta, databaseyear),
							% [{_, Databasemonth}] = ets:lookup(mymeta, databasemonth),
							% [{_, Databaseday}] = ets:lookup(mymeta, databaseday),
							[{_, Ipv4databasecount}] = ets:lookup(mymeta, ipv4databasecount),
							[{_, Ipv4databaseaddr}] = ets:lookup(mymeta, ipv4databaseaddr),
							[{_, Ipv6databasecount}] = ets:lookup(mymeta, ipv6databasecount),
							[{_, Ipv6databaseaddr}] = ets:lookup(mymeta, ipv6databaseaddr),
							[{_, Ipv4indexbaseaddr}] = ets:lookup(mymeta, ipv4indexbaseaddr),
							[{_, Ipv6indexbaseaddr}] = ets:lookup(mymeta, ipv6indexbaseaddr),
							[{_, Ipv4columnsize}] = ets:lookup(mymeta, ipv4columnsize),
							[{_, Ipv6columnsize}] = ets:lookup(mymeta, ipv6columnsize),
							
							Result = case inet:parse_address(Ip) of
								{ok, {X1, X2, X3, X4}} ->
									Ipnum = (X1 bsl 24) + (X2 bsl 16) + (X3 bsl 8) + (X4),
									search4(S, Ipnum, Databasetype, 0, Ipv4databasecount, Ipv4databaseaddr, Ipv4indexbaseaddr, Ipv4columnsize, Mode);
								{ok, {X1, X2, X3, X4, X5, X6, X7, X8}} ->
									Ipnum = (X1 bsl 112) + (X2 bsl 96) + (X3 bsl 80) + (X4 bsl 64) + (X5 bsl 48) + (X6 bsl 32) + (X7 bsl 16) + X8,
									if
										Ipnum >= Fromv4mapped andalso Ipnum =< Tov4mapped ->
											search4(S, (Ipnum - Fromv4mapped), Databasetype, 0, Ipv4databasecount, Ipv4databaseaddr, Ipv4indexbaseaddr, Ipv4columnsize, Mode);
										Ipnum >= From6to4 andalso Ipnum =< To6to4 ->
											search4(S, ((Ipnum bsr 80) band Last32bits), Databasetype, 0, Ipv4databasecount, Ipv4databaseaddr, Ipv4indexbaseaddr, Ipv4columnsize, Mode);
										Ipnum >= Fromteredo andalso Ipnum =< Toteredo ->
											search4(S, ((bnot Ipnum) band Last32bits), Databasetype, 0, Ipv4databasecount, Ipv4databaseaddr, Ipv4indexbaseaddr, Ipv4columnsize, Mode);
										true ->
											if
												Ipv6databasecount > 0 ->
													search6(S, Ipnum, Databasetype, 0, Ipv6databasecount, Ipv6databaseaddr, Ipv6indexbaseaddr, Ipv6columnsize, Mode);
												true ->
													#ip2proxyrecord{
													country_short = Z,
													country_long = Z,
													region = Z,
													city = Z,
													isp = Z,
													proxy_type = Z,
													domain = Z,
													usage_type = Z,
													asn = Z,
													as = Z,
													last_seen = Z,
													threat = Z,
													provider = Z,
													is_proxy = -1
													}
											end
									end;
								{_, _} ->
									#ip2proxyrecord{
									country_short = X,
									country_long = X,
									region = X,
									city = X,
									isp = X,
									proxy_type = X,
									domain = X,
									usage_type = X,
									asn = X,
									as = X,
									last_seen = X,
									threat = X,
									provider = X,
									is_proxy = -1
									}
							end,
							file:close(S),
							Result;
						_ ->
							#ip2proxyrecord{
							country_short = Y,
							country_long = Y,
							region = Y,
							city = Y,
							isp = Y,
							proxy_type = Y,
							domain = Y,
							usage_type = Y,
							asn = Y,
							as = Y,
							last_seen = Y,
							threat = Y,
							provider = Y,
							is_proxy = -1
							}
					end
			end
	end.

close() ->
	case ets:info(mymeta) of
		undefined ->
			ok; % do nothing
		_ ->
			ets:delete(mymeta)
	end,
	0. % zero means successful

closews() ->
	case ets:info(myws) of
		undefined ->
			ok;
		_ ->
			ets:delete(myws),
			ok
	end.

configurews(APIKey, APIPackage, UseSSL) ->
	_ = closews(),
	
	case ets:info(myws) of
		undefined ->
			ets:new(myws, [set, named_table]),
			ets:insert(myws, {apikey, APIKey}),
			ets:insert(myws, {apipackage, APIPackage}),
			ets:insert(myws, {usessl, UseSSL}),
			ok;
		_ ->
			ok
	end.

checkparams(APIKey, APIPackage) ->
	RegExp = "^[\\dA-Z]{10}$",
	RegExp2 = "^PX\\d+$",
	case re:run(APIKey, RegExp) of
		{match, _} ->
			case re:run(APIPackage, RegExp2) of
				nomatch ->
					io:format("Invalid package name.~n", []),
					halt();
				{match, _} ->
					ok % do nothing
			end;
		nomatch ->
			io:format("Invalid API key.~n", []),
			halt()
	end.


openws(APIKey, APIPackage, UseSSL) ->
	case checkparams(APIKey, APIPackage) of
		ok ->
			case UseSSL of
				false ->
					configurews(APIKey, APIPackage, UseSSL);
				_ ->
					configurews(APIKey, APIPackage, true)
			end;
		_ ->
			-1 % should have been halted in checkparams
	end.

readjson(Body) ->
	Body2 = string:trim(Body, leading, "{\""),
	Body3 = string:trim(Body2, trailing, "\"}"),
	L = string:split(Body3, "\",\"", all),
	F = fun(Elem, Acc) -> [list_to_tuple(string:split(Elem, "\":\"")) | Acc] end,
	maps:from_list(lists:foldl(F, [], L)).


lookup(IPAddress) ->
	ssl:start(),
	inets:start(),
	
	case ets:info(myws) of
		undefined ->
			io:format("Run openws first.~n", []),
			halt();
		_ ->
			case ets:lookup(myws, apikey) of
				[] ->
					io:format("Run openws first.~n", []),
					halt();
				[{_, APIKey}] ->
					case ets:lookup(myws, apipackage) of
						[] ->
							io:format("Run openws first.~n", []),
							halt();
						[{_, APIPackage}] ->
							case ets:lookup(myws, usessl) of
								[] ->
									io:format("Run openws first.~n", []),
									halt();
								[{_, UseSSL}] ->
									case UseSSL of
										true ->
											Protocol = "https";
										_ ->
											Protocol = "http"
									end,
									MyParams = uri_string:compose_query([{"key", APIKey}, {"package", APIPackage}, {"ip", IPAddress}]),
									
									case httpc:request(get, {Protocol ++ "://api.ip2proxy.com/?" ++ MyParams, []}, [{ssl, [{versions, ['tlsv1.2']}]}, {autoredirect, false}], []) of
										{ok, {{_, 200, _}, _, Body}} ->
											% Body2 = string:trim(Body, leading, "{\""),
											% Body3 = string:trim(Body2, trailing, "\"}"),
											% L = string:split(Body3, "\",\"", all),
											% F = fun(Elem, Acc) -> [list_to_tuple(string:split(Elem, "\":\"")) | Acc] end,
											% Map = maps:from_list(lists:foldl(F, [], L)),
											
											Map = readjson(Body),
											
											Response = case maps:is_key("response", Map) of
												true ->
													maps:get("response", Map);
												_ ->
													""
											end,
											CountryCode = case maps:is_key("countryCode", Map) of
												true ->
													maps:get("countryCode", Map);
												_ ->
													""
											end,
											CountryName = case maps:is_key("countryName", Map) of
												true ->
													maps:get("countryName", Map);
												_ ->
													""
											end,
											RegionName = case maps:is_key("regionName", Map) of
												true ->
													maps:get("regionName", Map);
												_ ->
													""
											end,
											CityName = case maps:is_key("cityName", Map) of
												true ->
													maps:get("cityName", Map);
												_ ->
													""
											end,
											ISP = case maps:is_key("isp", Map) of
												true ->
													maps:get("isp", Map);
												_ ->
													""
											end,
											ProxyType = case maps:is_key("proxyType", Map) of
												true ->
													maps:get("proxyType", Map);
												_ ->
													""
											end,
											Domain = case maps:is_key("domain", Map) of
												true ->
													maps:get("domain", Map);
												_ ->
													""
											end,
											UsageType = case maps:is_key("usageType", Map) of
												true ->
													maps:get("usageType", Map);
												_ ->
													""
											end,
											ASN = case maps:is_key("asn", Map) of
												true ->
													maps:get("asn", Map);
												_ ->
													""
											end,
											AS = case maps:is_key("as", Map) of
												true ->
													maps:get("as", Map);
												_ ->
													""
											end,
											LastSeen = case maps:is_key("lastSeen", Map) of
												true ->
													maps:get("lastSeen", Map);
												_ ->
													""
											end,
											Threat = case maps:is_key("threat", Map) of
												true ->
													maps:get("threat", Map);
												_ ->
													""
											end,
											Provider = case maps:is_key("provider", Map) of
												true ->
													maps:get("provider", Map);
												_ ->
													""
											end,
											IsProxy = case maps:is_key("isProxy", Map) of
												true ->
													maps:get("isProxy", Map);
												_ ->
													""
											end,
											
											#ip2proxyresult{
												response = Response,
												countryCode = CountryCode,
												countryName = CountryName,
												regionName = RegionName,
												cityName = CityName,
												isp = ISP,
												proxyType = ProxyType,
												domain = Domain,
												usageType = UsageType,
												asn = ASN,
												as = AS,
												lastSeen = LastSeen,
												threat = Threat,
												provider = Provider,
												isProxy = IsProxy
											};
										{error, Reason} ->
											{error, Reason}
									end
							end
					end
			end
	end.

getcredit() ->
	ssl:start(),
	inets:start(),
	
	case ets:info(myws) of
		undefined ->
			io:format("Run openws first.~n", []),
			halt();
		_ ->
			case ets:lookup(myws, apikey) of
				[] ->
					io:format("Run openws first.~n", []),
					halt();
				[{_, APIKey}] ->
					case ets:lookup(myws, usessl) of
						[] ->
							io:format("Run openws first.~n", []),
							halt();
						[{_, UseSSL}] ->
							case UseSSL of
								true ->
									Protocol = "https";
								_ ->
									Protocol = "http"
							end,
							MyParams = uri_string:compose_query([{"key", APIKey}, {"check", "true"}]),
							
							case httpc:request(get, {Protocol ++ "://api.ip2proxy.com/?" ++ MyParams, []}, [{ssl, [{versions, ['tlsv1.2']}]}, {autoredirect, false}], []) of
								{ok, {{_, 200, _}, _, Body}} ->
									% Body2 = string:trim(Body, leading, "{\""),
									% Body3 = string:trim(Body2, trailing, "\"}"),
									% L = string:split(Body3, "\",\"", all),
									% F = fun(Elem, Acc) -> [list_to_tuple(string:split(Elem, "\":\"")) | Acc] end,
									% Map = maps:from_list(lists:foldl(F, [], L)),
									Map = readjson(Body),
									
									case maps:is_key("response", Map) of
										true ->
											maps:get("response", Map);
										_ ->
											""
									end;
								{error, Reason} ->
									{error, Reason}
							end
					end
			end
	end.
