-module(ip2proxy).
-export([getpackageversion/0, getmoduleversion/0, getdatabaseversion/0, open/1, getall/1, getproxytype/1, getcountryshort/1, getcountrylong/1, getregion/1, getcity/1, getisp/1, getdomain/1, getusagetype/1, getasn/1, getas/1, getlastseen/1, isproxy/1, close/0]).
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
	is_proxy = 0
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
	"2.2.0".

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

readuint(S, StartPos, Len) ->
	case file:pread(S, StartPos - 1, Len) of
	eof ->
		ok;
	{ok, Data} ->
		binary:decode_unsigned(Data, little)
	end.

readuintrow(R, StartPos, Len) ->
	Data = binary:part(R, StartPos, Len),
	binary:decode_unsigned(Data, little).

readuint8(S, StartPos) ->
	readuint(S, StartPos, 1).

readuint32(S, StartPos) ->
	readuint(S, StartPos, 4).

readuint32row(R, StartPos) ->
	readuintrow(R, StartPos, 4).

readuint128(S, StartPos) ->
	readuint(S, StartPos, 16).

readstr(S, StartPos) ->
	case file:pread(S, StartPos, 1) of
	eof ->
		ok;
	{ok, LenRaw} ->
		Len = binary:decode_unsigned(LenRaw, little),
		case file:pread(S, StartPos + 1, Len) of
		eof ->
			ok;
		{ok, Data} ->
			binary_to_list(Data)
		end
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
		Databasetype = readuint8(S, 1),
		Databasecolumn = readuint8(S, 2),
		Databaseyear = readuint8(S, 3),
		Databasemonth = readuint8(S, 4),
		Databaseday = readuint8(S, 5),
		Ipv4databasecount = readuint32(S, 6),
		Ipv4databaseaddr = readuint32(S, 10),
		Ipv6databasecount = readuint32(S, 14),
		Ipv6databaseaddr = readuint32(S, 18),
		Ipv4indexbaseaddr = readuint32(S, 22),
		Ipv6indexbaseaddr = readuint32(S, 26),
		Ipv4columnsize = Databasecolumn bsl 2, % 4 bytes each column
		Ipv6columnsize = 16 + ((Databasecolumn - 1) bsl 2), % 4 bytes each column, except IPFrom column which is 16 bytes
		file:close(S),
		
		case ets:info(mymeta) of
		undefined ->
			ets:new(mymeta, [set, named_table]);
		_ ->
			ok % do nothing
		end,
		
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
		-1 % negative one means error
	end.

% readcolcountry(S, Dbtype, Rowoffset, Col) ->
	% X = "NOT SUPPORTED",
	% case lists:nth(Dbtype, Col) of
	% 0 ->
		% {X, X};
	% Colpos ->
		% Coloffset = (Colpos - 1) bsl 2,
		% X0 = readuint32(S, Rowoffset + Coloffset),
		% X1 = readstr(S, X0),
		% X2 = readstr(S, X0 + 3),
		% {X1, X2}
	% end.

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

% readcolstring(S, Dbtype, Rowoffset, Col) ->
	% case lists:nth(Dbtype, Col) of
	% 0 ->
		% "NOT SUPPORTED";
	% Colpos ->
		% Coloffset = (Colpos - 1) bsl 2,
		% readstr(S, readuint32(S, Rowoffset + Coloffset))
	% end.

readcolstringrow(S, R, Dbtype, Col) ->
	case lists:nth(Dbtype, Col) of
	0 ->
		"NOT SUPPORTED";
	Colpos ->
		Coloffset = (Colpos - 2) bsl 2,
		readstr(S, readuint32row(R, Coloffset))
	end.

readrecord(S, Dbtype, Rowoffset, Mode) ->
	Country_position = [0, 2, 3, 3, 3, 3, 3, 3, 3],
	Region_position = [0, 0, 0, 4, 4, 4, 4, 4, 4],
	City_position = [0, 0, 0, 5, 5, 5, 5, 5, 5],
	Isp_position = [0, 0, 0, 0, 6, 6, 6, 6, 6],
	Proxytype_position = [0, 0, 2, 2, 2, 2, 2, 2, 2],
	Domain_position = [0, 0, 0, 0, 0, 7, 7, 7, 7],
	Usagetype_position = [0, 0, 0, 0, 0, 0, 8, 8, 8],
	Asn_position = [0, 0, 0, 0, 0, 0, 0, 9, 9],
	As_position = [0, 0, 0, 0, 0, 0, 0, 10, 10],
	Lastseen_position = [0, 0, 0, 0, 0, 0, 0, 0, 11],
	
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
	
	Cols = ?IF(lists:nth(Dbtype, Country_position) == 0) + ?IF(lists:nth(Dbtype, Region_position) == 0) + ?IF(lists:nth(Dbtype, City_position) == 0) + ?IF(lists:nth(Dbtype, Isp_position) == 0) + ?IF(lists:nth(Dbtype, Proxytype_position) == 0) + ?IF(lists:nth(Dbtype, Domain_position) == 0) + ?IF(lists:nth(Dbtype, Usagetype_position) == 0) + ?IF(lists:nth(Dbtype, Asn_position) == 0) + ?IF(lists:nth(Dbtype, As_position) == 0) + ?IF(lists:nth(Dbtype, Lastseen_position) == 0),
	Rowlength = Cols bsl 2,
	
	case file:pread(S, Rowoffset - 1, Rowlength) of
		eof ->
			#ip2proxyrecord{};
		{ok, Data} ->
			R = Data,
			
			if
				(Mode band Proxytype_field /= 0) or (Mode band Isproxy_field /= 0) ->
					% Proxy_type = readcolstring(S, Dbtype, Rowoffset, Proxytype_position);
					Proxy_type = readcolstringrow(S, R, Dbtype, Proxytype_position);
				true ->
					Proxy_type = ""
			end,
			
			if
				(Mode band Countryshort_field /= 0) or (Mode band Countrylong_field /= 0) or (Mode band Isproxy_field /= 0) ->
					% {Country_short, Country_long} = readcolcountry(S, Dbtype, Rowoffset, Country_position);
					{Country_short, Country_long} = readcolcountryrow(S, R, Dbtype, Country_position);
				true ->
					{Country_short, Country_long} = {"", ""}
			end,
			
			if
				Mode band Region_field /= 0 ->
					% Region = readcolstring(S, Dbtype, Rowoffset, Region_position);
					Region = readcolstringrow(S, R, Dbtype, Region_position);
				true ->
					Region = ""
			end,
			
			if
				Mode band City_field /= 0 ->
					% City = readcolstring(S, Dbtype, Rowoffset, City_position);
					City = readcolstringrow(S, R, Dbtype, City_position);
				true ->
					City = ""
			end,
			
			if
				Mode band Isp_field /= 0 ->
					% Isp = readcolstring(S, Dbtype, Rowoffset, Isp_position);
					Isp = readcolstringrow(S, R, Dbtype, Isp_position);
				true ->
					Isp = ""
			end,
			
			if
				Mode band Domain_field /= 0 ->
					% Domain = readcolstring(S, Dbtype, Rowoffset, Domain_position);
					Domain = readcolstringrow(S, R, Dbtype, Domain_position);
				true ->
					Domain = ""
			end,
			
			if
				Mode band Usagetype_field /= 0 ->
					% Usage_type = readcolstring(S, Dbtype, Rowoffset, Usagetype_position);
					Usage_type = readcolstringrow(S, R, Dbtype, Usagetype_position);
				true ->
					Usage_type = ""
			end,
			
			if
				Mode band Asn_field /= 0 ->
					% Asn = readcolstring(S, Dbtype, Rowoffset, Asn_position);
					Asn = readcolstringrow(S, R, Dbtype, Asn_position);
				true ->
					Asn = ""
			end,
			
			if
				Mode band As_field /= 0 ->
					% As = readcolstring(S, Dbtype, Rowoffset, As_position);
					As = readcolstringrow(S, R, Dbtype, As_position);
				true ->
					As = ""
			end,
			
			if
				Mode band Lastseen_field /= 0 ->
					% Last_seen = readcolstring(S, Dbtype, Rowoffset, Lastseen_position);
					Last_seen = readcolstringrow(S, R, Dbtype, Lastseen_position);
				true ->
					Last_seen = ""
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
			is_proxy = Is_proxy
			}
	end.

searchtree(S, Ipnum, Dbtype, Low, High, BaseAddr, Colsize, Iptype, Mode) ->
	X = "INVALID IP ADDRESS",
	
	if
		Low =< High ->
			Mid = ((Low + High) bsr 1),
			Rowoffset = BaseAddr + (Mid * Colsize),
			Rowoffset2 = Rowoffset + Colsize,
			
			if
				Iptype == ipv4 ->
					Ipfrom = readuint32(S, Rowoffset),
					Ipto = readuint32(S, Rowoffset2);
				true ->
					Ipfrom = readuint128(S, Rowoffset),
					Ipto = readuint128(S, Rowoffset2)
			end,
			
			if
				Ipnum >= Ipfrom andalso Ipnum < Ipto ->
					if
						Iptype == ipv4 ->
							% readrecord(S, Dbtype + 1, Rowoffset, Mode);
							readrecord(S, Dbtype + 1, Rowoffset + 4, Mode);
						true ->
							% readrecord(S, Dbtype + 1, Rowoffset + 12, Mode)
							readrecord(S, Dbtype + 1, Rowoffset + 16, Mode)
					end;
				true ->
					if
						Ipnum < Ipfrom ->
							searchtree(S, Ipnum, Dbtype, Low, Mid - 1, BaseAddr, Colsize, Iptype, Mode);
						true ->
							searchtree(S, Ipnum, Dbtype, Mid + 1, High, BaseAddr, Colsize, Iptype, Mode)
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
			is_proxy = -1
			}
	end.

search4(S, Ipnum, Dbtype, Low, High, Baseaddr, Indexbaseaddr, Colsize, Mode) ->
	if
		Indexbaseaddr > 0 ->
			Indexpos = ((Ipnum bsr 16) bsl 3) + Indexbaseaddr,
			Low2 = readuint32(S, Indexpos),
			High2 = readuint32(S, Indexpos + 4),
			searchtree(S, Ipnum, Dbtype, Low2, High2, Baseaddr, Colsize, ipv4, Mode);
		true ->
			searchtree(S, Ipnum, Dbtype, Low, High, Baseaddr, Colsize, ipv4, Mode)
	end.

search6(S, Ipnum, Dbtype, Low, High, Baseaddr, Indexbaseaddr, Colsize, Mode) ->
	if
		Indexbaseaddr > 0 ->
			Indexpos = ((Ipnum bsr 112) bsl 3) + Indexbaseaddr,
			Low2 = readuint32(S, Indexpos),
			High2 = readuint32(S, Indexpos + 4),
			searchtree(S, Ipnum, Dbtype, Low2, High2, Baseaddr, Colsize, ipv6, Mode);
		true ->
			searchtree(S, Ipnum, Dbtype, Low, High, Baseaddr, Colsize, ipv6, Mode)
	end.

getall(Ip) ->
	query(Ip, 4095).

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

isproxy(Ip) ->
	Result = query(Ip, 64),
	Result#ip2proxyrecord.is_proxy.

query(Ip, Mode) ->
	X = "INVALID IP ADDRESS",
	Y = "INVALID BIN FILE",
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
							search4(S, Ipnum - Fromv4mapped, Databasetype, 0, Ipv4databasecount, Ipv4databaseaddr, Ipv4indexbaseaddr, Ipv4columnsize, Mode);
						Ipnum >= From6to4 andalso Ipnum =< To6to4 ->
							search4(S, (Ipnum bsr 80) band Last32bits, Databasetype, 0, Ipv4databasecount, Ipv4databaseaddr, Ipv4indexbaseaddr, Ipv4columnsize, Mode);
						Ipnum >= Fromteredo andalso Ipnum =< Toteredo ->
							search4(S, ((bnot Ipnum) band Last32bits), Databasetype, 0, Ipv4databasecount, Ipv4databaseaddr, Ipv4indexbaseaddr, Ipv4columnsize, Mode);
						true ->
							search6(S, Ipnum, Databasetype, 0, Ipv6databasecount, Ipv6databaseaddr, Ipv6indexbaseaddr, Ipv6columnsize, Mode)
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
