-module(ip2proxy).
-export([getpackageversion/0, getmoduleversion/0, getdatabaseversion/0, open/1, getall/1, getproxytype/1, getcountryshort/1, getcountrylong/1, getregion/1, getcity/1, getisp/1, isproxy/1, close/0]).
-record(ip2proxyrecord, {
	country_short = "-",
	country_long = "-",
	region = "-",
	city = "-",
	isp = "-",
	proxy_type = "-",
	is_proxy = 0
}).

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
	"1.0.0".

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

readuint8(S, StartPos) ->
	readuint(S, StartPos, 1).

readuint32(S, StartPos) ->
	readuint(S, StartPos, 4).

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

readcolcountry(S, Dbtype, Rowoffset, Col) ->
	X = "NOT SUPPORTED",
	case lists:nth(Dbtype, Col) of
	0 ->
		{X, X};
	Colpos ->
		Coloffset = (Colpos - 1) bsl 2,
		X0 = readuint32(S, Rowoffset + Coloffset),
		X1 = readstr(S, X0),
		X2 = readstr(S, X0 + 3),
		{X1, X2}
	end.

readcolstring(S, Dbtype, Rowoffset, Col) ->
	case lists:nth(Dbtype, Col) of
	0 ->
		"NOT SUPPORTED";
	Colpos ->
		Coloffset = (Colpos - 1) bsl 2,
		readstr(S, readuint32(S, Rowoffset + Coloffset))
	end.
	

readrecord(S, Dbtype, Rowoffset, Mode) ->
	Country_position = [0, 2, 3, 3, 3],
	Region_position = [0, 0, 0, 4, 4],
	City_position = [0, 0, 0, 5, 5],
	Isp_position = [0, 0, 0, 0, 6],
	Proxytype_position = [0, 0, 2, 2, 2],
	
	Countryshort_field = 1,
	Countrylong_field = 2,
	Region_field = 4,
	City_field = 8,
	Isp_field = 16,
	Proxytype_field = 32,
	Isproxy_field = 64,
	
	if
		(Mode band Proxytype_field /= 0) or (Mode band Isproxy_field /= 0) ->
			Proxy_type = readcolstring(S, Dbtype, Rowoffset, Proxytype_position);
		true ->
			Proxy_type = ""
	end,
	
	if
		(Mode band Countryshort_field /= 0) or (Mode band Countrylong_field /= 0) or (Mode band Isproxy_field /= 0) ->
			{Country_short, Country_long} = readcolcountry(S, Dbtype, Rowoffset, Country_position);
		true ->
			{Country_short, Country_long} = {"", ""}
	end,
	
	if
		Mode band Region_field /= 0 ->
			Region = readcolstring(S, Dbtype, Rowoffset, Region_position);
		true ->
			Region = ""
	end,
	
	if
		Mode band City_field /= 0 ->
			City = readcolstring(S, Dbtype, Rowoffset, City_position);
		true ->
			City = ""
	end,
	
	if
		Mode band Isp_field /= 0 ->
			Isp = readcolstring(S, Dbtype, Rowoffset, Isp_position);
		true ->
			Isp = ""
	end,
	
	if
		(Country_short == "-") or (Proxy_type == "-") ->
			Is_proxy = 0;
		true ->
			if
				Proxy_type == "DCH" ->
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
	is_proxy = Is_proxy
	}.

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
							readrecord(S, Dbtype + 1, Rowoffset, Mode);
						true ->
							readrecord(S, Dbtype + 1, Rowoffset + 12, Mode)
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
	query(Ip, 127).

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

isproxy(Ip) ->
	Result = query(Ip, 64),
	Result#ip2proxyrecord.is_proxy.

query(Ip, Mode) ->
	X = "INVALID IP ADDRESS",
	Y = "INVALID BIN FILE",
	From = 281470681743360,
	To = 281474976710655,
	
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
				
				case inet:parse_address(Ip) of
				{ok, {X1, X2, X3, X4}} ->
					Ipnum = (X1 bsl 24) + (X2 bsl 16) + (X3 bsl 8) + (X4),
					search4(S, Ipnum, Databasetype, 0, Ipv4databasecount, Ipv4databaseaddr, Ipv4indexbaseaddr, Ipv4columnsize, Mode);
				{ok, {X1, X2, X3, X4, X5, X6, X7, X8}} ->
					Ipnum = (X1 bsl 112) + (X2 bsl 96) + (X3 bsl 80) + (X4 bsl 64) + (X5 bsl 48) + (X6 bsl 32) + (X7 bsl 16) + X8,
					if
						Ipnum >= From andalso Ipnum =< To ->
							search4(S, Ipnum - From, Databasetype, 0, Ipv4databasecount, Ipv4databaseaddr, Ipv4indexbaseaddr, Ipv4columnsize, Mode);
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
					is_proxy = -1
					}
				end;
			_ ->
				#ip2proxyrecord{
				country_short = Y,
				country_long = Y,
				region = Y,
				city = Y,
				isp = Y,
				proxy_type = Y,
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
