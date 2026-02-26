module CIFS;

@load base/frameworks/logging/writers/ascii
redef LogAscii::use_json = T;
@load ./cp437
@load ./svtype

export {

	redef enum Log::ID += { LOG };

	type Info: record {
		ts:	time &log &optional;
		SrcIP:	addr &log &optional;
		SrcMAC: string &log &optional;
		ServerName: string &log &optional;
		Domain_Workgroup: string &log &optional;
		OSVersion: string &log &optional;
		ServerType: string &log &optional;
		ServerTypeRoles: string &log &optional;
		BrowserVersion: string &log &optional;
		Signature: string &log &optional;
		MysteriousField: string &log &optional;
		HostComment: string &log &optional;
		MasterBrowser: string &log &optional;
		UnusedFlags: string &log &optional;
		ComputerName: string &log &optional;
		MailSlotName: string &log &optional;
		UnicodeComputerName: string &log &optional;
		NtVersion: string &log &optional;
		LMNT_Token: string &log &optional;
		LM20_Token: string &log &optional;

		# Set to block number of final piece of data once received.
		final_block: count &optional;

		# Set to true once logged.
		done: bool &default=F;
	};

	## Event that can be handled to access the cifs logging record.
	global log_cifs: event(rec: Info);

	global res_endCode: table[string] of string = { ["\x00\x00"] = "nomal",
	                                    ["\xCF\x80"] = "stop",
										};

	global Cc: set[string] = { "\x00", "\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07", "\x08", "\x09", "\x0a", "\x0b"
								, "\x0c", "\x0d", "\x0e", "\x0f", "\x10", "\x11", "\x12", "\x13", "\x14", "\x15", "\x16", "\x17"
								, "\x18", "\x19", "\x1a", "\x1b", "\x1c", "\x1d", "\x1e", "\x1f", "\x7f"};

	type AggregationData: record {
		SrcIP:	addr &log &optional;
		SrcMAC: string &log &optional;
		ServerName: string &log &optional;
		Domain_Workgroup: string &log &optional; #
		OSVersion: string &log &optional;
		ServerType: string &log &optional;
		ServerTypeRoles: string &log &optional;
		BrowserVersion: string &log &optional;
		Signature: string &log &optional;
		MysteriousField: string &log &optional; #
		HostComment: string &log &optional;
		MasterBrowser: string &log &optional; #
        UnusedFlags: string &log &optional; #
		ComputerName: string &log &optional;
		MailSlotName: string &log &optional;
		UnicodeComputerName: string &log &optional;
		NtVersion: string &log &optional;
		LMNT_Token: string &log &optional;
		LM20_Token: string &log &optional;
	};

	type Ts_num: record {
		ts_s:			time &log;
		num: 			int &log;
		ts_e: 			time &log &optional;
	};

	function insert_log(res_aggregationData: table[AggregationData] of Ts_num, idx: AggregationData): interval
	{
	local info_insert: Info = [];
	info_insert$ts = res_aggregationData[idx]$ts_s;
	if ( idx?$SrcIP ){
		info_insert$SrcIP = idx$SrcIP;
	}
	if ( idx?$SrcMAC ){
		info_insert$SrcMAC = idx$SrcMAC;
	}
	if ( idx?$ServerName ){
		info_insert$ServerName = idx$ServerName;
	}
	if ( idx?$Domain_Workgroup ){
		info_insert$Domain_Workgroup = idx$Domain_Workgroup;
	}
	if ( idx?$OSVersion ){
		info_insert$OSVersion = idx$OSVersion;
	}
	if ( idx?$ServerType ){
		info_insert$ServerType = idx$ServerType;
	}
	if ( idx?$ServerTypeRoles ){
		info_insert$ServerTypeRoles = idx$ServerTypeRoles;
	}
	if ( idx?$BrowserVersion ){
		info_insert$BrowserVersion = idx$BrowserVersion;
	}
	if ( idx?$Signature ){
		info_insert$Signature = idx$Signature;
	}
	if ( idx?$MysteriousField){
		info_insert$MysteriousField = idx$MysteriousField;
	}
	if ( idx?$HostComment ){
		info_insert$HostComment = idx$HostComment;
	}
	if ( idx?$MasterBrowser){
		info_insert$MasterBrowser = idx$MasterBrowser;
	}
	if ( idx?$UnusedFlags){
		info_insert$UnusedFlags = idx$UnusedFlags;
	}
	if ( idx?$ComputerName){
		info_insert$ComputerName = idx$ComputerName;
	}
	if ( idx?$MailSlotName){
		info_insert$MailSlotName = idx$MailSlotName;
	}
	if ( idx?$UnicodeComputerName){
		info_insert$UnicodeComputerName = idx$UnicodeComputerName;
	}
	if ( idx?$NtVersion){
		info_insert$NtVersion = idx$NtVersion;
	}
	if ( idx?$LMNT_Token){
		info_insert$LMNT_Token = idx$LMNT_Token;
	}
	if ( idx?$LM20_Token){
		info_insert$LM20_Token = idx$LM20_Token;
	}
	# if ( res_aggregationData[idx]?$ts_e ){
	# 	info_insert$ts_end = res_aggregationData[idx]$ts_e;
	# }
	# if ( res_aggregationData[idx]?$num ){
	# 	info_insert$pkts = res_aggregationData[idx]$num;
	# }
	# print res_aggregationData;
	# print info;
	Log::write(CIFS::LOG, info_insert);
	# res_aggregationData = {};
	return 0secs;
	}

	global res_aggregationData: table[AggregationData] of Ts_num &create_expire=60sec &expire_func=insert_log;
}

function create_aggregationData(info: Info): AggregationData
	{
	local aggregationData: AggregationData;

	if ( info?$SrcIP ){
		aggregationData$SrcIP = info$SrcIP;
	}
	if ( info?$SrcMAC ){
		aggregationData$SrcMAC = info$SrcMAC;
	}
	if ( info?$ServerName ){
		aggregationData$ServerName = info$ServerName;
	}
	if ( info?$Domain_Workgroup ){
		aggregationData$Domain_Workgroup = info$Domain_Workgroup;
	}
	if ( info?$OSVersion ){
		aggregationData$OSVersion = info$OSVersion;
	}
	if ( info?$ServerType ){
		aggregationData$ServerType = info$ServerType;
	}
	if ( info?$ServerTypeRoles){
		aggregationData$ServerTypeRoles = info$ServerTypeRoles;
	}
	if ( info?$BrowserVersion ){
		aggregationData$BrowserVersion = info$BrowserVersion;
	}
	if ( info?$Signature ){
		aggregationData$Signature = info$Signature;
	}
	if ( info?$MysteriousField ){
		aggregationData$MysteriousField = info$MysteriousField;
	}
	if ( info?$HostComment ){
		aggregationData$HostComment = info$HostComment;
	}
	if ( info?$MasterBrowser ){
		aggregationData$MasterBrowser = info$MasterBrowser;
	}
	if ( info?$UnusedFlags ){
		aggregationData$UnusedFlags = info$UnusedFlags;
	}
	if ( info?$ComputerName ){
		aggregationData$ComputerName = info$ComputerName;
	}
	if ( info?$MailSlotName ){
		aggregationData$MailSlotName = info$MailSlotName;
	}
	if ( info?$UnicodeComputerName ){
		aggregationData$UnicodeComputerName = info$UnicodeComputerName;
	}
	if ( info?$NtVersion ){
		aggregationData$NtVersion = info$NtVersion;
	}
	if ( info?$LMNT_Token ){
		aggregationData$LMNT_Token = info$LMNT_Token;
	}
	if ( info?$LM20_Token ){
		aggregationData$LM20_Token = info$LM20_Token;
	}
	return aggregationData;
	}

function insert_res_aggregationData(aggregationData: AggregationData, info: Info): string
	{
		if (aggregationData in res_aggregationData){
			res_aggregationData[aggregationData]$num = res_aggregationData[aggregationData]$num + 1;
			res_aggregationData[aggregationData]$ts_e = info$ts;
		} else {
			res_aggregationData[aggregationData] = [$ts_s = info$ts, $num = 1, $ts_e = info$ts];
		}

		return "done";
	}

# Maps a partial data connection ID to the request's Info record.
global expected_data_conns: table[addr, port, addr] of Info;

redef record connection += {
	cifs: Info &optional;
};

#JSON
event zeek_init()
    {
    Log::create_stream(CIFS::LOG,
        [$columns=Info, $ev=log_cifs, $path="cifs"]);

    Log::remove_default_filter(CIFS::LOG);

    Log::add_filter(CIFS::LOG,
        [$name="json",
         $writer=Log::WRITER_ASCII,
         $config=table(
         ["use_json"]="T"
         )
        ]);
    }


function find_string(s: string): string
	{
	# local x = "\x00";
	local res = "";

	for ( c in s )
		{
		if ( c in Cc )
			{
			next;
			}
		else
			{
			res = res + c;
			}
		}
	if ( res == "" )
		{
		return "";
		}

	return res;
	}

# Basit ve sağlam: UTF-16LE içinde ASCII karakterleri çıkarır.
# (high byte 0x00 varsayımı; high byte 0x00 değilse '?' koyar)
function utf16le_to_utf8(b: string): string
    {
    local out = "";
    local i: count = 0;

    while ( i + 1 < |b| )
        {
        local lo = b[i:i+1];
        local hi = b[i+1:i+2];

        # null-terminator (0x0000)
        if ( lo == "\x00" && hi == "\x00" )
            break;

        if ( hi == "\x00" )
            out += lo;       # ASCII
        else
            out += "?";      # ASCII dışıysa basit fallback

        i += 2;
        }

    return out;
    }



# İlk NUL (0x00) geldiğinde durur
function cstr_until_nul(s: string): string
    {
    local out = "";
    for ( c in s )
        {
        if ( c == "\x00" )
            break;
        out += c;
        }
    return out;
    }

event CIFS::hostAnnouncement(
	c: connection, serverName: string, osversion_1: int, osversion_2: int,
	serverType_1: int, serverType_2: int, serverType_3: int, serverType_4: int,
	browserVersion_1: int, browserVersion_2: int, signature_1: string, signature_2: string,
	hostComment: string
	)
	{
	local info: Info;
	local aggregationData: AggregationData;

	local sn_raw = cstr_until_nul(serverName);
    sn_raw = CP437::strip_nb_suffix_and_pad(sn_raw);
    local sn_utf8  = CP437::cp437_to_utf8(sn_raw);

    local roles     = SVTYPE::decode_from_bytes(serverType_1, serverType_2, serverType_3, serverType_4);
    local roles_str = SVTYPE::join(roles, ",");

	info$ts = network_time();
	info$SrcIP = c$id$orig_h;
	info$SrcMAC = c$orig$l2_addr;
	info$ServerName = CP437::sanitize_nb_name(sn_utf8);
	info$OSVersion = cat(osversion_1) + "." + cat(osversion_2);
	info$ServerType = roles_str;
	info$BrowserVersion = cat(browserVersion_1) + "." + cat(browserVersion_2);
	info$Signature = "0x" + string_to_ascii_hex(signature_2) + string_to_ascii_hex(signature_1);
	info$HostComment = find_string(hostComment);

	# Log::write(CIFS::LOG,info);
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);
	c$cifs = info;
	# print fmt("Zeek saw from %s %s to %s: %s host", c$start_time, c$id$orig_h, c$id$resp_h, c$orig$l2_addr);
	}

event CIFS::localMasterAnnouncement(
	c: connection, serverName: string, osversion_1: int, osversion_2: int,
	serverType_1: int, serverType_2: int, serverType_3: int, serverType_4: int,
	browserVersion_1: int, browserVersion_2: int, signature_1: string, signature_2: string,
	hostComment: string
	)
	{

	local info: Info;
	local aggregationData: AggregationData;
	local sn_raw = cstr_until_nul(serverName);
    sn_raw = CP437::strip_nb_suffix_and_pad(sn_raw);
    local sn_utf8  = CP437::cp437_to_utf8(sn_raw);

    local roles = SVTYPE::decode_from_bytes(serverType_1, serverType_2, serverType_3, serverType_4);
    local roles_str = SVTYPE::join(roles, ",");

	info$ts = network_time();
	info$SrcIP = c$id$orig_h;
	info$SrcMAC = c$orig$l2_addr;
	info$ServerName = CP437::sanitize_nb_name(sn_utf8);
	info$OSVersion = cat(osversion_1) + "." + cat(osversion_2);
	info$ServerType = roles_str;
	info$BrowserVersion = cat(browserVersion_1) + "." + cat(browserVersion_2);
	info$Signature = "0x" + string_to_ascii_hex(signature_2) + string_to_ascii_hex(signature_1);
	info$HostComment = find_string(hostComment);

	# Log::write(CIFS::LOG,info);
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);
	c$cifs = info;
	# print fmt("Zeek saw from %s %s to %s: %s %s local", c$start_time, c$id$orig_h, c$id$resp_h, c$orig$l2_addr, network_time());
	}

event CIFS::domainWorkgroup(
	c: connection, domain_workgroup: string, osversion_1: int, osversion_2: int,
	serverType_1: int, serverType_2: int, serverType_3: int, serverType_4: int,
	mysteriousField: string, master_browser: string
	)
	{
	local info: Info;
	local aggregationData: AggregationData;
	local dw_raw = cstr_until_nul(domain_workgroup);
    dw_raw = CP437::strip_nb_suffix_and_pad(dw_raw);
    local dw_utf8  = CP437::cp437_to_utf8(dw_raw);

    local roles = SVTYPE::decode_from_bytes(serverType_1, serverType_2, serverType_3, serverType_4);
    local roles_str = SVTYPE::join(roles, ",");

	info$ts = network_time();
	info$SrcIP = c$id$orig_h;
	info$SrcMAC = c$orig$l2_addr;
	info$Domain_Workgroup = CP437::sanitize_nb_name(dw_utf8);
	info$OSVersion = cat(osversion_1) + "." + cat(osversion_2);
	info$ServerType = roles_str;
	info$MysteriousField = "0x" + string_to_ascii_hex(mysteriousField);
	info$MasterBrowser = find_string(master_browser);

	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);
	c$cifs = info;
	}

event CIFS::requestAnnouncement(
    c: connection, unusedFlags : string, computerName : string
    )
    {
    local info: Info;
	local aggregationData: AggregationData;
	local cn_raw = cstr_until_nul(computerName);
    cn_raw = CP437::strip_nb_suffix_and_pad(cn_raw);
    local cn_utf8  = CP437::cp437_to_utf8(cn_raw);

    info$ts    = network_time();
    info$SrcIP = c$id$orig_h;
    info$SrcMAC = c$orig$l2_addr;
    info$UnusedFlags = "0x" + string_to_ascii_hex(unusedFlags);
    info$ComputerName = CP437::sanitize_nb_name(cn_utf8);

	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);
	c$cifs = info;
    }

event CIFS::queryForPDC(
    c: connection, computerName : string, payload_mailslot : string, unicode_computer_name : string,
    ntVersion : int, lmntToken : string, lm20Token : string
    )
    {
    local info: Info;
	local aggregationData: AggregationData;


    local cn_raw = cstr_until_nul(computerName);
    cn_raw = CP437::strip_nb_suffix_and_pad(cn_raw);
    local cn_utf8  = CP437::cp437_to_utf8(cn_raw);

    local ms_raw = cstr_until_nul(payload_mailslot);
    ms_raw = CP437::strip_nb_suffix_and_pad(ms_raw);
    local ms_utf8  = CP437::cp437_to_utf8(ms_raw);

    local ucn_raw = cstr_until_nul(unicode_computer_name);
    ucn_raw = CP437::strip_nb_suffix_and_pad(ucn_raw);
    local ucn_utf8  = CP437::cp437_to_utf8(ucn_raw);

    info$ts    = network_time();
    info$SrcIP = c$id$orig_h;
    info$SrcMAC = c$orig$l2_addr;

    info$ComputerName = CP437::sanitize_nb_name(cn_utf8);
    info$MailSlotName = CP437::sanitize_nb_name(ms_utf8);
    info$UnicodeComputerName = utf16le_to_utf8(unicode_computer_name);
    info$NtVersion           = cat(ntVersion);
    info$LMNT_Token          = "0x" + string_to_ascii_hex(lmntToken);
    info$LM20_Token          = "0x" + string_to_ascii_hex(lm20Token);

    aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);
	c$cifs = info;
    }


# 集約 local debug用
event zeek_done()
	{
	# print "zeek_done()";
	# print res_aggregationData;
	for ( i in res_aggregationData ){
		# print i;
        # print res_aggregationData[i];
		local info: Info = [];
		info$ts = res_aggregationData[i]$ts_s;
		if ( i?$SrcIP ){
			info$SrcIP = i$SrcIP;
		}
		if ( i?$SrcMAC ){
			info$SrcMAC = i$SrcMAC;
		}
		if ( i?$ServerName ){
			info$ServerName = i$ServerName;
		}
		if ( i?$Domain_Workgroup ){
			info$Domain_Workgroup = i$Domain_Workgroup;
		}
		if ( i?$OSVersion ){
			info$OSVersion = i$OSVersion;
		}
		if ( i?$ServerType ){
			info$ServerType = i$ServerType;
		}
		if ( i?$BrowserVersion ){
			info$BrowserVersion = i$BrowserVersion;
		}
		if ( i?$Signature ){
			info$Signature = i$Signature;
		}
		if ( i?$MysteriousField ){
			info$MysteriousField = i$MysteriousField;
		}
		if ( i?$HostComment ){
			info$HostComment = i$HostComment;
		}
		if ( i?$MasterBrowser ){
			info$MasterBrowser = i$MasterBrowser;
		}
		if ( i?$UnusedFlags){
			info$UnusedFlags = i$UnusedFlags;
		}
		if ( i?$ComputerName  ){
			info$ComputerName = i$ComputerName;
		}
		if ( i?$MailSlotName  ){
			info$MailSlotName = i$MailSlotName;
		}
		if ( i?$UnicodeComputerName  ){
			info$UnicodeComputerName = i$UnicodeComputerName;
		}
		if ( i?$NtVersion  ){
			info$NtVersion = i$NtVersion;
		}
		if ( i?$LMNT_Token  ){
			info$LMNT_Token = i$LMNT_Token;
		}
		if ( i?$LM20_Token  ){
			info$LM20_Token = i$LM20_Token;
		}
		# if ( res_aggregationData[i]?$ts_e ){
		# 	info$ts_end = res_aggregationData[i]$ts_e;
		# }
		# if ( res_aggregationData[i]?$num ){
		# 	info$pkts = res_aggregationData[i]$num;
		# }
		# print res_aggregationData;
		# print info;
		Log::write(CIFS::LOG, info);
    	}
	}
