#!/usr/bin/awk -f

##############################################################################
### SCALAR (C) 2003, Yuri N. Fominov, YuriF@risk.az, http://scalar.risk.az ###
###	       Version 0.96						   ###
###            Designed to Analyze Native SQUID 2+ access.log files        ###
###            Usage: scalar logfilename				   ###
###                                                                        ### 
############################################################################## 

# Note, You might need to modify path to AWK above #


BEGIN { yes=1; Yes=1; YES=1; no=0; No=0; NO=0;

### REPORTING OPTIONS ##################################################

count_hosts     = yes	# count unique hosts accessed cache
count_time_use  = yes	# count and draw requests/traffic by hours
count_hierarchy = yes	# count Cache Hierarchy (requests to peers) 
count_filetypes = yes	# count File Types / extensions (extension report)
count_proto	= yes	# count protocols/ports usage
count_obj_size	= yes	# count objects size distribution
count_squid_code= yes	# count Squid's result codes (TCP_HIT and etc...)
count_http_code = yes	# count HTTP result codes (OK/200 and etc...)
count_methods	= yes	# count HTTP request methods (GET, POST and etc...)

# Note, Each of above reports may slow down SCALAR performance, 
#       so you can choose most necessary for better performance.


max_extensions 	= 50    # maximum extenstions in extensions report
max_protoports 	= 10 	# still not implemented
use_ansii_colors= yes   # enable ansii colors (esc sequences)
time_offset 	= 4     # UTC time offset
graph_scale	= 20    # height of rows, used for Time Charts
progress_update = 5000 	# every n lines (0 to disable)

### MAINTENANCE OPTIONS ################################################

disable_systime = no



### FIELDS SETUP (for Customized, non-standard log formats) ###########

f_ts		= 1
f_speed		= 2
f_source	= 3
f_host		= 3
f_status	= 4
f_size		= 5
f_method	= 6
f_url		= 7
f_hrc		= 9
f_mime		= 10


### ADVANCED SETUP OPTIONS ##############################################

### Protocols & Ports (Protocols & Ports Report)

proto_port[11]   = "DayTime"
proto_port[21]   = "FTP"
proto_port[22]   = "SSH"
proto_port[23]   = "Telnet"
proto_port[25]   = "SMTP"
proto_port[79]   = "Finger"
proto_port[80]   = "HTTP"
proto_port[110]  = "POP3"
proto_port[111]  = "RPC"
proto_port[115]  = "SFTP"
proto_port[123]  = "NTP"
proto_port[143]  = "IMAP"
proto_port[161]  = "SNMP"
proto_port[443]  = "HTTPS"
proto_port[465]  = "SMTPS"
proto_port[585]  = "IMAP-SSL"
proto_port[636]  = "LDAPS"
proto_port[901]  = "SWAT"
proto_port[993]  = "IMAPS"
proto_port[995]  = "POP3S"
proto_port[1352] = "LotusNotes"
proto_port[1525] = "Oracle"
proto_port[5190] = "AOL/ICQ"
proto_port[6666] = "IRC"
proto_port[6667] = "IRC"
proto_port[6668] = "IRC"
proto_port[6669] = "IRC"
proto_port[7000] = "IRC"


### Object Size Difinitions, (Object Size Report)

size_scale_max= 12
size_scale[1] = 100             ; name_scale[1] = "  0-0.1KB"
size_scale[2] = 1024            ; name_scale[2] = "0.1-1.0KB"
size_scale[3] = 5*1024          ; name_scale[3] = "  1-5  KB"
size_scale[4] = 10*1024         ; name_scale[4] = "  5-10 KB"
size_scale[5] = 50*1024         ; name_scale[5] = " 10-50 KB"
size_scale[6] = 100*1024        ; name_scale[6] = " 50-100KB"
size_scale[7] = 500*1024        ; name_scale[7] = "100-500KB"
size_scale[8] = 1*1024^2	; name_scale[8] = "0.5-1.0MB"
size_scale[9] = 5*1024^2        ; name_scale[9] = "  1-5  MB"
size_scale[10]= 10*1024^2       ; name_scale[10]= "  5-10 MB"
size_scale[11]= 50*1024^2       ; name_scale[11]= " 10-50 MB"
size_scale[12]= 100*1024^2      ; name_scale[12]= " 50-100MB"
                                  name_scale[13]= "   >100MB"


### Content Type Definition Settings (ext. report)

obj_type[1] 	 = "htm|xml"
obj_type_name[1] = "Web Pages: Static"

obj_type[2] 	 = "js|class|jar|vbs|css"
obj_type_name[2] = "Java, VBS & CSS"

obj_type[3] 	 = "mp2|mp3|wav|ogg|wma|mpc|mid|aif|wal|snd|voc|snd|miz|stm|ape|flac|mkv|s3m|spx|xm"
obj_type_name[3] = "Media: Audio"

obj_type[4] 	 = "mpg|mpe|avi|divx|xvid|wmv|mov|m2v|ogm|ifo|vcd|vob"
obj_type_name[4] = "Media: Video"

obj_type[5] 	 = "swf|jpg|jpe|gif|tif|png|pcx|bmp|psd|cdr|ai|wmf|cgm|ico"
obj_type_name[5] = "Images/Graphics & Flash"

obj_type[6] 	 = "exe|ex_|com|zip|tar|gz|rar|r[0-9][0-9]|ace"
obj_type_name[6] = "Archives & Executables"

obj_type[7] 	 = "dll|avc|x86|klb|set|vnd|isu|cab|trg|gsz"
obj_type_name[7] = "Software Updates"

obj_type[8] 	 = "QUERY"
obj_type_name[8] = "<QUERY>"

obj_type[9] 	 = "\/"
obj_type_name[9] = "/ -any content possible"

obj_type[10] 	 = "asf|nsv|rm|ra"
obj_type_name[10]= "Streaming Audio/Video"

obj_type[11]     = "pdf|doc|xls|xlt|xlm|xla|xlc|dot|ppt"
obj_type_name[11]= "PDF & MS Office Files"

obj_type[12]     = "asp|jsp|php|pl|nsf|cgi|cf"
obj_type_name[12]= "Web Pages: Dynamic"

obj_type[13]     = "txt|csv|diz|nfo|rtf"
obj_type_name[13]= "Text & RTF Files"

obj_type[14]     = "vbp|mak|vbg|ocx|pas|bas|cpp|asm|\c$|\h$"
obj_type_name[14]= "Dev. Source Code"

max_obj_types 	 = 14

obj_type_name[max_obj_types+1] = "[other]"
				  

############################################################################
### !!! DO NOT MODIFY ANYTHING BELOW  !! ###################################

consider_none   = 0 ;  consider_name[consider_none]	= "NONE"
consider_hit 	= 1 ;  consider_name[consider_hit]     	= "HIT"
consider_miss	= 2 ;  consider_name[consider_miss] 	= "MISS"
consider_deny	= 3 ;  consider_name[consider_deny]     = "DENY"
consider_uhit   = 4 ;  consider_name[consider_uhit]     = "UDP HIT"
consider_umiss  = 5 ;  consider_name[consider_umiss]    = "UDP MISS"
consider_direct = 6 ;  consider_name[consider_direct]   = "DIRECT"
consider_OK     = 8 ;  consider_name[consider_OK]       = "OK"
consider_error  = 9 ;  consider_name[consider_error]    = "ERROR"
consider_udp    = 10 ; consider_name[consider_udp]      = "UDP"
consider_timeout= 11 ; consider_name[consider_timeout]  = "TIMEOUT"
consider_other  = 12 ; consider_name[consider_other]    = "OTHER"

consider_fetch_miss    = 13
consider_fetch_hit     = 14
consider_peer_timeout  = 15
consider_direct_timeout= 16

status_cons["TCP_HIT"]      	       = consider_hit
status_cons["TCP_MISS"]      	       = consider_miss
status_cons["TCP_REFRESH_HIT"]         = consider_hit
status_cons["TCP_REF_FAIL_HIT"]        = consider_hit
status_cons["TCP_REFRESH_MISS"]        = consider_miss
status_cons["TCP_CLIENT_REFRESH_MISS"] = consider_miss
status_cons["TCP_IMS_HIT"]             = consider_hit
status_cons["TCP_SWAPFAIL_MISS"]       = consider_miss
status_cons["TCP_NEGATIVE_HIT"]        = consider_hit
status_cons["TCP_MEM_HIT"]     	       = consider_hit
status_cons["TCP_OFFLINE_HIT"]         = consider_hit
status_cons["UDP_HIT"]     	       = consider_uhit
status_cons["UDP_MISS"]     	       = consider_umiss
status_cons["UDP_DENIED"]     	       = consider_deny
status_cons["UDP_INVALID"]     	       = consider_none
status_cons["UDP_MISS_NOFETCH"]        = consider_umiss
status_cons["TCP_DENIED"]     	       = consider_deny

status_code_name[0]   = "UDP Traffic"
status_code_name["000"]="UDP Traffic"
status_code_name[100] = "Continue"
status_code_name[101] = "Switching Protocols"
status_code_name[102] = "Processing"

status_code_cons[0]   = consider_udp
status_code_cons["000"]= consider_udp
status_code_cons[100] = consider_other
status_code_cons[101] = consider_other
status_code_cons[102] = consider_other

status_code_name[200] = "OK"
status_code_name[201] = "Created"
status_code_name[202] = "Accepted"
status_code_name[203] = "Non-Authoritative Info."
status_code_name[204] = "No Content"
status_code_name[205] = "Reset Content"
status_code_name[206] = "Parital Content"
status_code_name[207] = "Multi Status"

status_code_cons[200] = consider_OK
status_code_cons[201] = consider_OK
status_code_cons[202] = consider_OK
status_code_cons[203] = consider_other
status_code_cons[204] = consider_other
status_code_cons[205] = consider_other
status_code_cons[206] = consider_OK
status_code_cons[207] = consider_OK

status_code_name[300] = "Multiple Choices"
status_code_name[301] = "Moved Permanently"
status_code_name[302] = "Moved Temporarily"
status_code_name[303] = "See Other"
status_code_name[304] = "Not Modified"
status_code_name[305] = "Use Proxy"
status_code_name[307] = "Temporary Redirect"

status_code_cons[300] = consider_OK
status_code_cons[301] = consider_other
status_code_cons[302] = consider_other
status_code_cons[303] = consider_other
status_code_cons[304] = consider_OK
status_code_cons[305] = consider_other
status_code_cons[307] = consider_OK

status_code_name[400] = "Bad Request"
status_code_name[401] = "Unauthorized"
status_code_name[402] = "Payment Required"
status_code_name[403] = "Forbidden"
status_code_name[404] = "Not Found"
status_code_name[405] = "Method Not Allowed"
status_code_name[406] = "Not Acceptable"
status_code_name[407] = "Proxy Auth. Required"
status_code_name[408] = "Request Timeout"
status_code_name[409] = "Conflict"
status_code_name[410] = "Gone"
status_code_name[411] = "Length Reqiured"
status_code_name[412] = "Precondition Failed"
status_code_name[413] = "Request Entity Too Large"
status_code_name[414] = "Request URI Too Large"
status_code_name[415] = "Unsupported Media Type"
status_code_name[416] = "Request Range Not Satif."
status_code_name[417] = "Expectation Failed"
status_code_name[423] = "Locked"
status_code_name[424] = "Locked/Failed Dependency"
status_code_name[433] = "Unprocessable Entity"

status_code_cons[400] = consider_error
status_code_cons[401] = consider_deny
status_code_cons[402] = consider_deny
status_code_cons[403] = consider_deny
status_code_cons[404] = consider_error
status_code_cons[405] = consider_error
status_code_cons[406] = consider_deny
status_code_cons[407] = consider_error
status_code_cons[408] = consider_timeout
status_code_cons[409] = consider_error
status_code_cons[410] = consider_error
status_code_cons[411] = consider_error
status_code_cons[412] = consider_error
status_code_cons[413] = consider_error
status_code_cons[414] = consider_error
status_code_cons[415] = consider_error
status_code_cons[416] = consider_error
status_code_cons[417] = consider_error
status_code_cons[422] = consider_error
status_code_cons[423] = consider_error
status_code_cons[444] = consider_error

status_code_name[500] = "Internal Server Error"
status_code_name[501] = "Not Implemented"
status_code_name[502] = "Bad Gateway"
status_code_name[503] = "Service Unavailable"
status_code_name[504] = "Gateway Timeout"
status_code_name[505] = "HTTP Ver. Not Supported"
status_code_name[507] = "Insufficient Storage"
status_code_name[508] = "?????"
status_code_name[600] = "Squid Header Parse Err."

status_code_cons[500] = consider_error
status_code_cons[501] = consider_other
status_code_cons[502] = consider_error
status_code_cons[503] = consider_error
status_code_cons[504] = consider_timeout
status_code_cons[505] = consider_error
status_code_cons[507] = consider_error
status_code_cons[508] = consider_error
status_code_cons[600] = consider_error

peer_cons["NONE"]	 	= consider_none
peer_cons["DIRECT"]    	 	= consider_direct
peer_cons["SIBLING_HIT"]       	= consider_fetch_hit
peer_cons["PARENT_HIT"]       	= consider_fetch_hit
peer_cons["DEFAULT_PARENT"]     = consider_fetch_miss
peer_cons["SINGLE_PARENT"] 	= consider_fetch_miss
peer_cons["FIRST_UP_PARENT"]    = consider_fetch_miss
peer_cons["NO_PARENT_DIRECT"]   = consider_direct
peer_cons["FIRST_PARENT_MISS"]  = consider_fetch_miss
peer_cons["CLOSEST_PARENT_MISS"]= consider_fetch_miss
peer_cons["CLOSEST_PARENT"]     = consider_fecth_miss
peer_cons["CLOSEST_DIRECT"]     = consider_direct
peer_cons["NO_DIRECT_FAIL"]     = consider_deny
peer_cons["SOURCE_FASTEST"]     = consider_fetch_miss
peer_cons["ROUNDROBIN_PARENT"]  = consider_fetch_miss
peer_cons["CACHE_DIGEST_HIT"]   = consider_fetch_hit
peer_cons["CD_PARENT_HIT"]      = consider_fetch_hit
peer_cons["CD_SIBLING_HIT"]     = consider_fetch_hit
peer_cons["NO_CACHE_DIGEST_DIRECT"]= consider_fetch_miss
peer_cons["CARP"]               = consider_fetch_miss
peer_cons["ANY_PARENT"]         = consider_fetch_miss
peer_cons["INVALID CODE"]       = consider_deny
peer_cons["TIMEOUT_DIRECT"]     = consider_direct_timeout

peer_cons["TIMEOUT_SIBLING_HIT"]	= consider_peer_timeout
peer_cons["TIMEOUT_PARENT_HIT"]         = consider_peer_timeout
peer_cons["TIMEOUT_DEFAULT_PARENT"]    	= consider_peer_timeout
peer_cons["TIMEOUT_SINGLE_PARENT"]     	= consider_peer_timeout
peer_cons["TIMEOUT_FIRST_UP_PARENT"]   	= consider_peer_timeout
peer_cons["TIMEOUT_FIRST_PARENT_MISS"] 	= consider_peer_timeout
peer_cons["TIMEOUT_CLOSEST_PARENT_MISS"]= consider_peer_timeout
peer_cons["TIMEOUT_CLOSEST_PARENT"]    	= consider_peer_timeout
peer_cons["TIMEOUT_SOURCE_FASTEST"]     = consider_peer_timeout
peer_cons["TIMEOUT_ROUNDROBIN_PARENT"]  = consider_peer_timeout
peer_cons["TIMEOUT_CACHE_DIGEST_HIT"]   = consider_peer_timeout
peer_cons["TIMEOUT_CD_PARENT_HIT"]      = consider_peer_timeout
peer_cons["TIMEOUT_CD_SIBLING_HIT"]     = consider_peer_timeout
peer_cons["TIMEOUT_NO_CACHE_DIGEST_DIRECT"]= consider_peer_timeout
peer_cons["TIMEOUT_CARP"]               = consider_peer_timeout
peer_cons["TIMEOUT_ANY_PARENT"]         = consider_peer_timeout


##############################################################################

v=use_ansii_colors
ext_report_sort= 2 #total connects
vhl_on[1] ="\x01b[1m"
vhl_off[1]="\x01b[0m"

printf "\n" vhl_on[v] "\n"
printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
printf "~~~~  SCALAR (Squid Cache Advanced Log Analyzer & Reporter), Version 0.96  ~~~~\n"
printf "~~~~                                                                       ~~~~\n"
printf "~~~~  (C) 2003-4 by Yuri N. Fominov, YuriF@risk.az, http://scalar.risk.az  ~~~~\n"
printf "~~~~  SCALAR has no warranty and it is completely free, so you are welcome ~~~~\n"
printf "~~~~  to re-distribute this pretty useful piece of software. Good Luck2All ~~~~\n"
printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"

printf "\n" vhl_off[v] "\n"

SetTriggers()
FixStart()

}


### PROCESS ####################################################################

{
    if(first_line_time=="") {first_line_time=$f_ts}
    ShowProgress()
    CountStatus()
    if(count_time_use==1) {CountTime()}
    if(count_hosts==1) {CountHosts()}    
    last_line_time=$f_ts
}

### END ########################################################################

END {
    PreReport()
    if(count_time_use==1) {TimeReport()}    
    if(count_filetypes==1) {ExtReport()}
    if(count_obj_size ==1) {SizeReport()}
    if(count_squid_code==1) {StatusReport()}
    if(count_http_code==1) {StatusReport2()}
    if(count_methods==1)  {MethodsReport()}
    if(count_proto==1)    {ProtoReport()}
    if(count_hierarchy==1) {HrcReport()}

    PrintTitle("All Done. Enjoy Your Report.  /  SCALAR (C) 2004, http://scalar.risk.az")
}


### FUNCTIONS ###############################################################


function SetTriggers() { ####################################################

    mt[2] = 31 #feb
    mt[4] = 31 #apr
    mt[5] = 30 #may
    mt[6] = 31 #jun
    mt[7] = 30 #jul
    mt[8] = 31 #aug
    mt[9] = 31 #sep
    mt[10]= 30 #oct
    mt[11]= 31 #nov
    mt[12]= 30 #dec

    os_type = tolower(ENVIRON["OSTYPE"])
    
    if(os_type ~ "linux" && disable_systime==no) {
	count_elapsed = 1
	use_extended  = 1
    }

}
function MaxHosts() { #######################################################

    uniq_hosts=0
    for(hostname in host_conn) { uniq_hosts++ }
    return uniq_hosts
}


function CountHosts() { #####################################################

    host_conn[$f_host]++
    host_size[$f_host]+=$f_size
}


function PreReport() { ######################################################

    printf "                                                                                    "
    PrintTitle("Analysis Headlines")
    UTC(tsf,first_line_time+time_offset*3600)
    UTC(tsl,last_line_time +time_offset*3600)
    
    printf "  Log Start Time [" sprintf("%02d-%02d-%4d %02d:%02d:%02d",tsf[4],tsf[5],tsf[6],tsf[3],tsf[2],tsf[1]) "]\n"
    printf "    Log End Time [" sprintf("%02d-%02d-%4d %02d:%02d:%02d",tsl[4],tsl[5],tsl[6],tsl[3],tsl[2],tsl[1]) "]\n"
    printf "  Lines Analyzed  " ShortDigit(NR,"") "\n\n"

    if(count_elapsed==1) {printf "  Analysis Took: " systime()-start_time " sec.  Average: " int(NR/(systime()-start_time)) " Lines/sec\n\n"} 
    if(count_hosts==1)   {printf " Unique Clients: " MaxHosts() "\n\n"}
    
    printf "     In Traffic: " ShortDigit(global_other_size,"Bytes") "\n"
    printf "    Out Traffic: " ShortDigit(global_other_size+global_hit_size,"Bytes") "\n"
    printf "  ------------------------------------\n"
    printf "  Saved Traffic: " ShortDigit(global_hit_size,"Bytes") "  "
    printf "%s", sprintf("%6.2f",global_hit_size/(global_other_size+global_hit_size)*100) " %\n"
}


function TimeReport() { #####################################################

    PrintTitle("Requests By Hours")

    i=1
    while(i<=366) {
	k=0
	while(k<=23) {
	    if(time_count_conn[k,i] !=0) {
		new_days[k]++
		joint_hour_conn[k]+=time_count_conn[k,i]
		joint_hour_size[k]+=time_count_size[k,i]
	    }
	    k++
	}
	i++
    }

    k=0 
    while(k<=23) {
    
	if(new_days[k]>1) {
	    joint_hour_conn[k]=int(joint_hour_conn[k]/new_days[k])
	    joint_hour_size[k]=int(joint_hour_size[k]/new_days[k])
	}
    
	all_per_day_conn+=joint_hour_conn[k]
	all_per_day_size+=joint_hour_size[k]
	if(joint_hour_conn[k]>max_per_day_conn) {max_per_day_conn=joint_hour_conn[k]}
	if(joint_hour_size[k]>max_per_day_size) {max_per_day_size=joint_hour_size[k]}
	k++
    }

    k=0; min_per_day_conn = max_per_day_conn; min_per_day_size = max_per_day_size
    
    while(k<=23) {
	
	if(joint_hour_conn[k]<min_per_day_conn) {min_per_day_conn=joint_hour_conn[k]}
	if(joint_hour_size[k]<min_per_day_size) {min_per_day_size=joint_hour_size[k]}
	k++
    }


    avg_hour_conn=int(all_per_day_conn/24)
    avg_hour_size=int(all_per_day_size/24)
    scale_conn=int(max_per_day_conn/graph_scale)
    scale_size=int(max_per_day_size/graph_scale)
    
    i=graph_scale
    while(i>=1) {
	printf VeryShortDigit(scale_conn*i,"") " "
	k=0
	while(k<=23) {
	    if(joint_hour_conn[k]>=scale_conn*i) {
		printf " =="
	    } else { printf "   " }
	    k++
	}
	printf "\n"
	i--
    }
    
    bottom1= "_______________________________________________________________________________\n"
    bottom2= "  Hours: 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23\n"
    printf bottom1 bottom2
    
    printf "\nMaximum Requests:" ShortDigit(max_per_day_conn,"") "/hour, "
    printf ShortDigit(int(max_per_day_conn/60),"") "/min,"
    printf sprintf("%7.1f",max_per_day_conn/3600) "/sec.\n"
    
    printf "Average Requests:" ShortDigit(avg_hour_conn,"") "/hour, " 
    printf ShortDigit(int(avg_hour_conn)/60,"") "/min,"
    printf sprintf("%7.1f",avg_hour_conn/3600) "/sec.\n"

    printf "Minimum Requests:" ShortDigit(min_per_day_conn,"") "/hour, "
    printf ShortDigit(int(min_per_day_conn/60),"") "/min,"
    printf sprintf("%7.1f",min_per_day_conn/3600) "/sec.\n"
    
    PrintTitle("Traffic by Hours")

    i=graph_scale
    while(i>=1) {
        printf VeryShortDigit(scale_size*i,"Bytes")
        k=0
        while(k<=23) {
            if(joint_hour_size[k]>=scale_size*i) {
                    printf " =="
            } else { printf "   " }
            k++
        }
        printf "\n"
        i--
    }
					
    printf bottom1 bottom2
    printf "\nMaximum Xfers:" ShortDigit(max_per_day_size,"Bytes") "/hour, "
    printf ShortDigit(int(max_per_day_size/60),"Bytes") "/min,"
    printf ShortDigit(max_per_day_size/3600,"Bytes") "/sec ["
    printf sprintf("%4.0f", (max_per_day_size/3600*8)/1024) " kbps]\n"

    printf "Average Xfers:" ShortDigit(avg_hour_size,"Bytes") "/hour, "
    printf ShortDigit(int(avg_hour_size)/60,"Bytes") "/min,"
    printf ShortDigit(avg_hour_size/3600,"Bytes") "/sec ["
    printf sprintf("%4.0f", (avg_hour_size/3600*8)/1024) " kbps]\n"    

    printf "Minimum Xfers:" ShortDigit(min_per_day_size,"Bytes") "/hour, "
    printf ShortDigit(int(min_per_day_size/60),"Bytes") "/min,"
    printf ShortDigit(min_per_day_size/3600,"Bytes") "/sec ["
    printf sprintf("%4.0f", (min_per_day_size/3600*8)/1024) " kbps]\n"
}


function CountTime() { ######################################################

    UTCshort(ts1)
    time_count_conn[ts1[3],ts1[7]]++
    time_count_size[ts1[3],ts1[7]]+=$f_size
}


function HrcReport() { ######################################################

    i=0
    for(prn in peer_count) {
	i++
	peer_common[i,1] =prn
	peer_common[i,2] =peer_fetch_miss_conn[prn]
	peer_common[i,3] =peer_fetch_hit_conn[prn]
	peer_common[i,4] =peer_fetch_deny_conn[prn]
	peer_common[i,5] =peer_fetch_timeout_conn[prn]
	peer_common[i,6] =peer_common[i,2]+peer_common[i,3]+peer_common[i,4]+peer_common[i,5]
	peer_all_conn   +=peer_common[i,6]
    
        peer_common[i,7] =peer_fetch_miss_size[prn]
        peer_common[i,8] =peer_fetch_hit_size[prn]
        peer_common[i,9] =peer_fetch_deny_size[prn]
	peer_common[i,10]=peer_fetch_timeout_size[prn]
        peer_common[i,11]=peer_common[i,6]+peer_common[i,7]+peer_common[i,8]+peer_common[i,9]
        peer_all_size   +=peer_common[i,11]
    }
    
    max_peers=i
    
    if(max_peers<=1) {return}
    
    PrintTitle("Hierarchy (Requests)")
    printf "%s","Peer/Direct    |  Total   %VOL| Misses Miss% |  Hits   Hit% |  Deny  |Timeouts|\n"
    printf "%s","---------------|--------------|--------------|--------------|--------|--------|\n"
    
    DoNumSort(peer_common,max_peers,11,6)
    
    i=1
    while(i<=max_peers) {
    
	printf "%-15s",peer_common[i,1] 
	printf "%s",ShortDigit(peer_common[i,6],"") "  "
	printf "%s",sprintf("%3.0f",peer_common[i,6]/peer_all_conn*100) "%"
	printf "%s",ShortDigit(peer_common[i,2],"") " "
	printf "%s",sprintf("%3.0f",peer_common[i,2]/peer_common[i,6]*100) "% "
	printf "%s",ShortDigit(peer_common[i,3],"") " "
	printf "%s",sprintf("%3.0f",peer_common[i,3]/peer_common[i,6]*100) "% "
	printf "%s",ShortDigit(peer_common[i,4],"") 
	printf "%s",ShortDigit(peer_common[i,5],"") 
	printf "\n"
	i++
    }

    PrintTitle("Hierarchy (Traffic)")
    printf "%s","Peer/Direct    |  Total    %VOL| Misses    Miss% |    Hits    Hit% |Deny&T-out|\n"
    printf "%s","---------------|---------------|-----------------|-----------------|----------|\n"    

    DoNumSort(peer_common,max_peers,11,11)

    i=1
    while(i<=max_peers) {

        printf "%-15s",peer_common[i,1]
        printf "%s",ShortDigit(peer_common[i,11],"Bytes") " "
    	printf "%s",sprintf("%3.0f",peer_common[i,11]/peer_all_size*100) "%"
        printf "%s",ShortDigit(peer_common[i,7],"Bytes") "  "
        printf "%s",sprintf("%3.0f",peer_common[i,7]/peer_common[i,11]*100) "%  "
        printf "%s",ShortDigit(peer_common[i,8],"Bytes") " "
        printf "%s",sprintf("%3.0f",peer_common[i,8]/peer_common[i,11]*100) "% "
        printf "%s",ShortDigit(peer_common[i,9]+peer_common[i,10],"Bytes")
	printf "\n"		

        if(peer_common[i,1] != "DIRECT") {
	    all_peers_hit += peer_common[i,8]
            all_peers_miss+= peer_common[i,7]
    	    other_peers += peer_common[i,9] + peer_common[i,10]
	} else {
	    all_direct_hit += peer_common[i,8]
	    all_direct_miss+= peer_common[i,7]
	    other_direct += peer_common[i,9] + peer_common[i,10]
	}
	i++
    }

    PrintTitle("Hierarchy - Cumulative Traffic")
    printf "%s"," Group         |  Total    %VOL| Misses    Miss% |    Hits    Hit% |Deny&T-out|\n"
    dl3=        "---------------|---------------|-----------------|-----------------|----------|\n"
    printf "%s", dl3

    whole_traffic = other_peers + other_direct + all_peers_hit + all_peers_miss + all_direct_hit + all_direct_miss
    
    printf "DIRECT         "
    printf "%s", ShortDigit(all_direct_miss+all_direct_hit+other_direct,"Bytes") " "
    printf "%s", sprintf("%3.0f",(all_direct_miss+all_direct_hit+other_direct)/whole_traffic*100) "% "
    printf "%s", ShortDigit(all_direct_miss,"Bytes") " "
    printf "%s", sprintf("%3.0f",all_direct_miss/(all_direct_miss+all_direct_hit+other_direct)* 100) "%  "
    printf "%s", ShortDigit(all_direct_hit, "Bytes") " "
    printf "%s", sprintf("%3.0f",all_direct_hit/(all_direct_miss+all_direct_hit+other_direct)* 100) "% "
    printf "%s", ShortDigit(other_direct, "Bytes") "\n"

    printf "ALL PEERS      "
    printf "%s", ShortDigit(all_peers_miss+all_peers_hit + other_peers,"Bytes") " "
    printf "%s", sprintf("%3.0f",(all_peers_miss+all_peers_hit+other_peers)/whole_traffic*100) "% "
    printf "%s", ShortDigit(all_peers_miss,"Bytes") " "
    printf "%s", sprintf("%3.0f",all_peers_miss/(all_peers_miss+all_peers_hit+other_peers)* 100) "%  "
    printf "%s", ShortDigit(all_peers_hit, "Bytes") " "
    printf "%s", sprintf("%3.0f",all_peers_hit/(all_peers_miss+all_peers_hit+other_peers)* 100) "% "
    printf "%s", ShortDigit(other_peers, "Bytes") "\n"
		    
    printf "%s",dl3
    
    printf "DIRECT + PEERS "
    printf "%s", ShortDigit(whole_traffic,"Bytes") " "
    printf "%s", "100% " 
    printf "%s", ShortDigit(all_peers_miss+all_direct_miss,"Bytes") " "
    printf "%s", sprintf("%3.0f",(all_peers_miss+ all_direct_miss)/whole_traffic * 100) "%  "
    printf "%s", ShortDigit(all_peers_hit +all_direct_hit, "Bytes") " "
    printf "%s", sprintf("%3.0f",(all_peers_hit + all_direct_hit)/whole_traffic * 100) "% "
    printf "%s", ShortDigit(other_peers+other_direct, "Bytes") "\n"
}


function CountPeer(in_consider) { ###########################################

    if(count_hierarchy !=1) {return}

    hrc1 =split($f_hrc,pd,"/")
    
    if(peer_cons[pd[1]]==consider_direct || peer_cons[pd[1]]==consider_none) {

        if (in_consider==consider_miss) {
    	    peer_fetch_miss_conn["DIRECT"]++
    	    peer_fetch_miss_size["DIRECT"]+=$f_size
	    peer_count["DIRECT"]++
	    return }

        if(in_consider==consider_deny) {
	    peer_fetch_deny_conn["DIRECT"]++
	    peer_fetch_deny_size["DIRECT"]+=$f_size
	    peer_count["DIRECT"]++
	    return }
    }

    if(peer_cons[pd[1]]==consider_fetch_miss) {
	peer_fetch_miss_conn[pd[2]]++
	peer_fetch_miss_size[pd[2]]+=$f_size
	peer_count[pd[2]]++
	#print "fecth_miss: " pd[2] " " $f_hrc
	return }

    if(peer_cons[pd[1]]==consider_fetch_hit) {
        peer_fetch_hit_conn[pd[2]]++
        peer_fetch_hit_size[pd[2]]+=$f_size
	peer_count[pd[2]]++
        return }
				
    if(peer_cons[pd[1]]==consider_deny) {
        peer_fetch_deny_conn[pd[2]]++
        peer_fetch_deny_size[pd[2]]+=$f_size
	peer_count[pd[2]]++
        return }

    if(peer_cons[pd[1]]==consider_peer_timeout) {
        peer_fetch_timeout_conn[pd[2]]++
        peer_fetch_timeout_size[pd[2]]+=$f_size
	peer_count[pd[2]]++
        return }

    if(peer_cons[pd[1]]==consider_direct_timeout) {
        peer_fetch_timeout_conn[pd[2]]++
        peer_fetch_cache_timeout_size[pd[2]]+=$f_size
	peer_count["DIRECT"]++
        return }
}


function ProtoReport() { ####################################################

    port_common[1,1]= "[ALL]"
    port_common[1,2]= "HTTP"
    port_common[1,3]= proto_hit_conn["HTTP"] + port_hit_conn[80]
    port_common[1,4]= proto_hit_size["HTTP"] + port_hit_size[80]
    port_common[1,5]= proto_miss_conn["HTTP"] + port_miss_conn[80]
    port_common[1,6]= proto_miss_size["HTTP"] + port_miss_size[80]
    port_common[1,7]= proto_deny_conn["HTTP"] + port_deny_conn[80]
    port_common[1,8]= proto_deny_size["HTTP"] + port_deny_size[80]
    port_common[1,9]= port_common[1,3] + port_common[1,5] + port_common[1,7]
    port_common[1,10]=port_common[1,4] + port_common[1,6] + port_common[1,8]
    port_all_conn = port_common[1,9]
    port_all_size = port_common[1,10]

    delete port[80]
    delete port_hit_conn[80]
    delete port_hit_size[80]
    delete port_miss_conn[80]
    delete port_miss_size[80]
    delete port_deny_conn[80]
    delete port_deny_size[80]
			    
    port_common[2,1]= "[ALL]"
    port_common[2,2]= "FTP"
    port_common[2,3]= proto_hit_conn["FTP"] += port_hit_conn[21]
    port_common[2,4]= proto_hit_size["FTP"] += port_hit_size[21]
    port_common[2,5]= proto_miss_conn["FTP"] += port_miss_conn[21]
    port_common[2,6]= proto_miss_size["FTP"] += port_miss_size[21]
    port_common[2,7]= proto_deny_conn["FTP"] += port_deny_conn[21]
    port_common[2,8]= proto_deny_size["FTP"] += port_deny_size[21]
    port_common[2,9]= port_common[2,3] + port_common[2,5] + port_common[2,7]
    port_common[2,10]=port_common[2,4] + port_common[2,6] + port_common[2,8]
    port_all_conn += port_common[2,9]
    port_all_size += port_common[2,10]
	
    delete port[21]
    delete port_hit_conn[21]
    delete port_hit_size[21]
    delete port_miss_conn[21]
    delete port_miss_size[21]
    delete port_deny_conn[21]
    delete port_deny_size[21]

    i=3
    for (zp in port) {			
	port_common[i,1]= zp
        port_common[i,2]= proto_port[zp]
	port_common[i,3]= port_hit_conn[zp]
	port_common[i,4]= port_hit_size[zp]
	port_common[i,5]= port_miss_conn[zp]
	port_common[i,6]= port_miss_size[zp]
	port_common[i,7]= port_deny_conn[zp]
	port_common[i,8]= port_deny_size[zp]
	port_common[i,9]= port_common[i,3] + port_common[i,5] + port_common[i,7]
	port_common[i,10]=port_common[i,4] + port_common[i,6] + port_common[i,8]
	port_all_conn += port_common[i,9]
	port_all_size += port_common[i,10]
	i++			
    }

    max_ports =i
    
    DoNumSort(port_common,max_ports,10,9)

    PrintTitle("Protocols & Ports (Requests)")
    print " Port | Protocol  | Total    %VOL | Misses Miss% |  Hits   Hit% |  Deny  Deny%|"
    print "------|-----------|---------------|--------------|--------------|-------------|"

    i=1
    while (i<=max_ports) {
    
	if (port_common[i,9] !=0) {
	    
	    printf "%-7s", port_common[i,1]
	    printf "%-11s", port_common[i,2]
	    printf "%s", ShortDigit(port_common[i,9],"") ""
	    printf "%s", sprintf("%6.2f",port_common[i,9]/port_all_conn*100) "% "
	    printf "%s", ShortDigit(port_common[i,5],"") " "
	    printf "%s", sprintf("%3.0f",port_common[i,5]/port_common[i,9]*100) "% "
    	    printf "%s", ShortDigit(port_common[i,3],"") " "
	    printf "%s", sprintf("%3.0f",port_common[i,3]/port_common[i,9]*100) "%"
	    printf "%s", ShortDigit(port_common[i,7],"") " "
	    printf "%s", sprintf("%3.0f",port_common[i,7]/port_common[i,9]*100) "%"
	    printf "\n"
	    
	    tot_all_conn  += port_common[i,9]
	    tot_miss_conn += port_common[i,5]
	    tot_hit_conn  += port_common[i,3]
	    tot_deny_conn += port_common[i,7]
	}
	i++
    }

    print "==================|===============|==============|==============|=============|"
    printf "          TOTALS: "
    printf "%s", ShortDigit(tot_all_conn,"") "   100% "
    printf "%s", ShortDigit(tot_miss_conn,"") " "
    printf "%s", sprintf("%3.0f",tot_miss_conn/tot_all_conn*100) "% "
    printf "%s", ShortDigit(tot_hit_conn,"") " "
    printf "%s", sprintf("%3.0f",tot_hit_conn/tot_all_conn*100) "%"
    printf "%s", ShortDigit(tot_deny_conn,"") " "
    printf "%s", sprintf("%3.0f",tot_deny_conn/tot_all_conn*100) "%"
    printf "\n"

    DoNumSort(port_common,max_ports,10,10)

    PrintTitle("Protocols & Ports (Traffic)")
    print " Port | Protocol  |   Total    %VOL | Misses   Miss%|  Hits    Hit% |  Deny"
    print "------|-----------|-----------------|---------------|---------------|----------"

    i=1
    while (i<=max_ports) {
        if (port_common[i,10] !=0) {
            printf "%-7s", port_common[i,1]
            printf "%-11s", port_common[i,2]
            printf "%s", ShortDigit(port_common[i,10],"Bytes") " "
            printf "%s", sprintf("%5.2f",port_common[i,10]/port_all_size*100) "%"
	    printf "%s", ShortDigit(port_common[i,6],"Bytes") " "
            printf "%s", sprintf("%3.0f",port_common[i,6]/port_common[i,10]*100) "%"
            printf "%s", ShortDigit(port_common[i,4],"Bytes") " "
            printf "%s", sprintf("%3.0f",port_common[i,4]/port_common[i,10]*100) "%"
            printf "%s", ShortDigit(port_common[i,8],"Bytes") " "
	    printf "\n"

            tot_all_size  += port_common[i,10]
	    tot_miss_size += port_common[i,6]
	    tot_hit_size  += port_common[i,4]
	    tot_deny_size += port_common[i,8]
	}
	i++
    } 

    print "==================|=================|===============|===============|=========="
    
    printf "          TOTALS: "
    printf "%s", ShortDigit(tot_all_size,"Bytes") "   100%"
    printf "%s", ShortDigit(tot_miss_size,"Bytes") " "
    printf "%s", sprintf("%3.0f",tot_miss_size/tot_all_size*100) "%"
    printf "%s", ShortDigit(tot_hit_size,"Bytes") " "
    printf "%s", sprintf("%3.0f",tot_hit_size/tot_all_size*100) "%"
    printf "%s", ShortDigit(tot_deny_size,"Bytes")
    printf "\n"
}



function MethodsReport() { ##################################################

    PrintTitle("Request Methods")
    printf "%s","---------------|------- R E Q U E S T S -----|-------- T R A F F I C ---------|\n"
    printf "%s"," Method        |  %VOL  | Requests |  denied |  %VOL  |  Traffic   |  denied  |\n"
    printf "%s","---------------|--------|----------|---------|--------|------------|----------|\n"

    i=0
    for (rm in request_method_conn) {
	if (request_method_conn[rm]>0) {
	    i++
	    request_method[i,1] = rm
	    request_method[i,2] = request_method_conn[rm]
	    request_method[i,3] = request_method_size[rm]
	    request_method[i,4] = request_method_deny_conn[rm]
	    request_method[i,5] = request_method_deny_size[rm]
	    request_method_all_conn +=request_method[i,2]
	    request_method_all_size +=request_method[i,3]
	}
    }

    max_request_methods=i
    DoNumSort(request_method,max_request_methods,5,2)

    i=1
    while (i<=max_request_methods) {

        printf "%-17s", request_method[i,1]
	printf "%s", sprintf("%5.2f",request_method[i,2]/request_method_all_conn*100) "%  "
        printf ShortDigit(request_method[i,2],"") " "
	printf ShortDigit(request_method[i,4],"") "   "
        printf "%s", sprintf("%5.2f",request_method[i,3]/request_method_all_size*100) "%  "
	printf ShortDigit(request_method[i,3],"Bytes") ""
	printf ShortDigit(request_method[i,5],"Bytes") "\n"
	i++
    }		    
    printf "==============================================================================\n"
}


function StatusReport2() { ##################################################

    PrintTitle("HTTP Status Codes")
    printf " ## | Description/Name        | Requests  |  Traffic   |  Group  |\n"
    printf "----|-------------------------|-----------|------------|---------|\n"

    i=0
    for (sr2 in status_code_conn) {
        if (status_code_conn[sr2]>0) {
	    i++
	    status_code[i,1] = sr2 
	    status_code[i,2] = status_code_name[sr2]
	    status_code[i,3] = status_code_conn[sr2]
	    status_code[i,4] = status_code_size[sr2]
	    status_code_all_conn += status_code[i,3]
	    status_code_all_size += status_code[i,4]
	    
	    status_code_grp[status_code_cons[sr2],2] = consider_name[status_code_cons[sr2]]
	    status_code_grp[status_code_cons[sr2],3] += status_code[i,3]
	    status_code_grp[status_code_cons[sr2],4] += status_code[i,4]
	}
    }							

    max_status_codes=i
    DoNumSort(status_code,max_status_codes,4,3)
    DoNumSort(status_code_grp,50,4,3)

    i=1
    
    while (i<=max_status_codes) {
	
	printf status_code[i,1] "  "
	printf "%-27s", status_code[i,2] 
	printf ShortDigit(status_code[i,3],"") "   "
	printf ShortDigit(status_code[i,4],"Bytes") "  "
	printf consider_name[status_code_cons[status_code[i,1]]]
	printf "\n"
	i++
    }
    printf "==============================|===========|============|========|\n"
    printf "                      TOTALS:   "
    printf ShortDigit(status_code_all_conn,"") "   "
    printf ShortDigit(status_code_all_size,"Bytes") "\n\n\n"
    

    printf "%s"," Group         | Requests     %Vol      |     Traffic     %Vol  |\n"
    printf "%s","---------------|------------------------|-----------------------|\n"

    i=1
    while (status_code_grp[i,3] !=0) {
    
	printf "%-16s", status_code_grp[i,2] 
	printf ShortDigit(status_code_grp[i,3],"") "    "
	printf "%s", sprintf("%5.2f", status_code_grp[i,3]/status_code_all_conn*100) "%         "
	printf ShortDigit(status_code_grp[i,4],"Bytes") "  "
        printf "%s", sprintf("%5.2f", status_code_grp[i,4]/status_code_all_size*100) "%\n"
    
	i++
    }
    print "==============================================================="
}




function SizeReport() { #####################################################

    PrintTitle("Objects Size Report")
    print "---------|------ R E Q U E S T S  -------|----------- T R A F F I C -----------"
    print "  SIZE   |  total | misses |  hits  |hit%|   total  |  misses  |   hits   |hit%"
    print "---------|--------|--------|--------|----|----------|----------|----------|----"

    i=1
    while (i<=size_scale_max+1) {
    
	printf name_scale[i]     
	t11=size_array_conn[i,consider_miss]+size_array_conn[i,consider_hit]
	printf ShortDigit(t11,"") 
	printf ShortDigit(size_array_conn[i,consider_miss],"") 
        printf ShortDigit(size_array_conn[i,consider_hit],"") " "
	if (t11==0) { printf "%s","  0%" } else {
	printf "%s", sprintf("%3.0f",size_array_conn[i,consider_hit]/t11*100) "%" }
    
	t21=size_array_size[i,consider_miss]+size_array_size[i,consider_hit]
        printf ShortDigit(t21,"Bytes") 
        printf ShortDigit(size_array_size[i,consider_miss],"Bytes") 
        printf ShortDigit(size_array_size[i,consider_hit],"Bytes") " "
	if (t21==0) { printf "%s","  0%" } else {
	printf "%s", sprintf("%3.0f",size_array_size[i,consider_hit]/t21*100) "%" }
	printf "\n"
    
	i++
    }
    print "==============================================================================="
}




function ExtReport () { #####################################################

    i=0
    for (zz in obj_uniq) {
	if (obj_miss_conn[zz] + obj_hit_conn[zz] >0) {
	    i++
    	    obj_common[i,1]=zz
	    obj_common[i,2]=obj_miss_conn[zz] + obj_hit_conn[zz]
	    obj_common[i,3]=obj_miss_conn[zz]
	    if (obj_common[i,2]==0) {obj_common[i,4]=0} else {
	    obj_common[i,4]=(obj_common[i,3]/obj_common[i,2])*100 }
	    obj_common[i,5]=obj_hit_conn[zz]
	    obj_common[i,6]=obj_miss_size[zz] + obj_hit_size[zz]
	    obj_common[i,7]=obj_miss_size[zz]
	    if (obj_common[i,7]==0) {obj_common[i,8]=0} else {
	    obj_common[i,8]=(obj_common[i,7]/obj_common[i,6])*100 }
	    obj_common[i,9]=obj_hit_size[zz]
	}
    }

    obj_total=i

    DoNumSort(obj_common,obj_total,9,ext_report_sort)

    PrintTitle("File Extensions Report")
    print "-------|------ R E Q U E S T S  --------|----------- T R A F F I C -----------|"
    print " Ext.  |  total | misses |  hits  |hit% |   total  |  misses  |   hits   |hit%|"
    print "-------|--------|--------|--------|-----|----------|----------|----------|----|"

    
    if (max_extensions==0 ||max_extensions>=obj_total) {max_extensions=obj_total} else {

        i = max_extensions +1
	obj_common[max_extensions,1]="[other]"
	while (i<=obj_total) {
    
	    obj_common[max_extensions,2] += obj_common[i,2]
	    obj_common[max_extensions,3] += obj_common[i,3]
	    obj_common[max_extensions,5] += obj_common[i,5]
	    obj_common[max_extensions,6] += obj_common[i,6]
	    obj_common[max_extensions,7] += obj_common[i,7]
	    obj_common[max_extensions,9] += obj_common[i,9]
	    i++
	}
	
        if (obj_common[max_extensions,2]==0) {obj_common[max_extensions,4]=0} else {
	obj_common[max_extensions,4]=(obj_common[max_extensions,3]/obj_common[max_extensions,2])*100 }
			  
        if (obj_common[max_extensions,7]==0) {obj_common[max_extensions,8]=0} else {
	obj_common[max_extensions,8]=(obj_common[max_extensions,7]/obj_common[max_extensions,6])*100 }
			  	
	DoNumSort(obj_common,max_extensions,9,ext_report_sort)
    }
	
    i=1
    while (i<=max_extensions) {
    
	printf sprintf("%-7s",obj_common[i,1])
	printf ShortDigit(obj_common[i,2],"") ShortDigit(obj_common[i,3],"") ShortDigit(obj_common[i,5],"") " " 
	printf "%s", sprintf("%3.0f",100-obj_common[i,4]) "% "
	printf ShortDigit(obj_common[i,6],"Bytes")  ShortDigit(obj_common[i,7],"Bytes") ShortDigit(obj_common[i,9],"Bytes") " "
	printf "%s", sprintf("%3.0f",100-obj_common[i,8]) "%"
	printf "\n"
	
	obj_all_conn +=obj_common[i,2] ; obj_all_conn_miss +=obj_common[i,3] ; obj_all_conn_hit +=obj_common[i,5]
	obj_all_size +=obj_common[i,6] ; obj_all_size_miss +=obj_common[i,7] ; obj_all_size_hit +=obj_common[i,9]
	
	j=1
	obj_recognized=0
	while (j<=max_obj_types) {
	    if (obj_common[i,1] ~ obj_type[j]) {
		obj_recognized=1
		obj_grp[j,1] = obj_type_name[j]
		obj_grp[j,2] += obj_common[i,2]
		obj_grp[j,3] += obj_common[i,5]
		obj_grp[j,4] += obj_common[i,6]
		obj_grp[j,5] += obj_common[i,9]
	    }
	    j++
	}    
	
	if (obj_recognized == 0) {
            obj_grp[max_obj_types+1,1] =  obj_type_name[max_obj_types+1]
	    obj_grp[max_obj_types+1,2] += obj_common[i,2]
	    obj_grp[max_obj_types+1,3] += obj_common[i,5]
	    obj_grp[max_obj_types+1,4] += obj_common[i,6]
            obj_grp[max_obj_types+1,5] += obj_common[i,9]
	} 
	
	i++
    }

    printf "================|========|========|=====|==========|==========|==========|====|\n"
    printf "TOTALS:"
    printf ShortDigit(obj_all_conn,"") ShortDigit(obj_all_conn_miss,"") ShortDigit(obj_all_conn_hit,"") " "
    printf "%s", sprintf("%3.0f", (obj_all_conn_hit/obj_all_conn)*100) "% "
    printf ShortDigit(obj_all_size,"Bytes") ShortDigit(obj_all_size_miss,"Bytes") ShortDigit(obj_all_size_hit,"Bytes") " "
    printf "%s", sprintf("%3.0f", (obj_all_size_hit/obj_all_size)*100) "%"
    printf "\n\n\n"		    

    DoNumSort(obj_grp,max_obj_types+1,5,2)

    print "-----------------------|-- R E Q U E S T S ---|-------- T R A F F I C --------|"
    print " Content Type          |  total |  hits  |hit%|  total   |   hits   |hit%|%VOL|"
    print "-----------------------|--------|--------|----|----------|----------|----|----|"

    i=1
    while (i<=max_obj_types+1) {
	
	if (obj_grp[i,2]>0) {
	    printf "%-23s", obj_grp[i,1] 
    	    printf "%s", ShortDigit(obj_grp[i,2],"") 
	    printf "%s", ShortDigit(obj_grp[i,3],"") " "
	    printf "%s", sprintf("%3.f",obj_grp[i,3]/obj_grp[i,2]*100) "%"
	    printf "%s", ShortDigit(obj_grp[i,4],"Bytes") 
	    printf "%s", ShortDigit(obj_grp[i,5],"Bytes") " "
	    printf "%s", sprintf("%3.f",obj_grp[i,5]/obj_grp[i,4]*100) "% "
	    printf "%s", sprintf("%3.f",obj_grp[i,4]/obj_all_size *100) "%"
	    printf "\n"
	}
	i++
    }
    print "=============================================================================="
}



function StatusReport() { ######################################################

    hits=0 ; misses=0 ; deny=0 ;  none=0 ; uhits=0 ; umisses=0
    
    for (xx in status_uniq) {
	if (status_cons[xx]==consider_hit) {
	    hits++
	    status_common_hit[hits,1]=xx
    	    status_common_hit[hits,2]=status_conn[xx]
	    status_common_hit[hits,3]=status_size[xx] } 
	if (status_cons[xx]==consider_miss) {
    	    misses++
	    status_common_miss[misses,1]=xx
	    status_common_miss[misses,2]=status_conn[xx]
	    status_common_miss[misses,3]=status_size[xx] }
	if (status_cons[xx]==consider_deny) {
	    deny++
            status_common_deny[deny,1]=xx
	    status_common_deny[deny,2]=status_conn[xx]
	    status_common_deny[deny,3]=status_size[xx] }
        if (status_cons[xx]==consider_none) {
            none++
            status_common_none[none,1]=xx
            status_common_none[none,2]=status_conn[xx]
            status_common_none[none,3]=status_size[xx] }
        if (status_cons[xx]==consider_uhit) {
            uhits++
            status_common_uhit[uhits,1]=xx
            status_common_uhit[uhits,2]=status_conn[xx]
            status_common_uhit[uhits,3]=status_size[xx] }
        if (status_cons[xx]==consider_umiss) {
            umisses++
            status_common_umiss[umisses,1]=xx
            status_common_umiss[umisses,2]=status_conn[xx]
            status_common_umiss[umisses,3]=status_size[xx] }
    }

    DoNumSort(status_common_hit,hits,3,2)
    DoNumSort(status_common_miss,misses,3,2)
    DoNumSort(status_common_deny,deny,3,2)
    DoNumSort(status_common_uhit,uhits,3,2)
    DoNumSort(status_common_umiss,umisses,3,2)
    
    PrintTitle("Squid Result Codes")
    printf "|      Result Code       | Requests  |  Traffic   |\n"
    bl3=   "|------------------------|-----------|------------|\n"
    printf bl3
    
    i=1
    
    while (i<=hits) {
	all_hit_conn += status_common_hit[i,2]
	all_hit_size += status_common_hit[i,3]
	printf "%+26s", status_common_hit[i,1] "  "
	printf ShortDigit(status_common_hit[i,2],"") "    "
	printf ShortDigit(status_common_hit[i,3],"Bytes") "\n"
	i++
    }
    
    bl31=  "==================================================\n"
    prinf bl31
    printf "%+26s", "TOTAL HITS:" "  "
    printf ShortDigit(all_hit_conn, "") "    "
    printf ShortDigit(all_hit_size,"Bytes") "\n"    
    printf "\n" bl3
    
    i=1
    while (i<=misses) {
        all_miss_conn += status_common_miss[i,2]
        all_miss_size += status_common_miss[i,3]
        printf "%+26s", status_common_miss[i,1] "  "
        printf ShortDigit(status_common_miss[i,2],"") "    "
        printf ShortDigit(status_common_miss[i,3],"Bytes") "\n"
	i++
    }

    printf bl31				

    printf "%+26s", "TOTAL MISSES:" "  "
    printf ShortDigit(all_miss_conn, "") "    "
    printf ShortDigit(all_miss_size,"Bytes") "\n\n"
		    
    printf "%+28s", "TOTAL HITS VOLUME:"
    printf "%s", sprintf("%6.2f", all_hit_conn / (all_hit_conn + all_miss_conn)*100) " %      "
    printf "%s", sprintf("%6.2f", all_hit_size / (all_hit_size + all_miss_size)*100) " %\n"
    printf "\n" bl3    

    i=1
    while (i<=deny) {
        printf "%+26s", status_common_deny[i,1] "  "
        printf ShortDigit(status_common_deny[i,2],"") "    "
        printf ShortDigit(status_common_deny[i,3],"Bytes") "\n"
        i++
    }
							
    i=1
    while (i<=uhits) {
        printf "%+26s", status_common_uhit[i,1] "  "
        printf ShortDigit(status_common_uhit[i,2],"") "    "
        printf ShortDigit(status_common_uhit[i,3],"Bytes") "\n"
	i++
    }
    
    i=1
    while (i<=umisses) {
        printf "%+26s", status_common_umiss[i,1] "  "
        printf ShortDigit(status_common_umiss[i,2],"") "    "
        printf ShortDigit(status_common_umiss[i,3],"Bytes") "\n"
        i++
    }

    i=1					
    while (i<=none) {
        printf "%+26s", status_common_none[i,1] "  "
        printf ShortDigit(status_common_none[i,2],"") "    "
        printf ShortDigit(status_common_none[i,3],"Bytes") "\n"
        i++
    }

    printf bl31					
}


function CountStatus() { #######################################################

  if(count_filetypes==1) {ext=GetExt($f_url)}
    
    z= split($f_status,a1,"/")

  if(count_squid_code==1) {    
    status_uniq[a1[1]]++
    status_conn[a1[1]]++
    status_size[a1[1]]+= $f_size
  }

  if(count_http_code==1) {
    status_code_conn[a1[2]]++
    status_code_size[a1[2]]+= $f_size
  }
  
  if(count_methods==1) {
    request_method_conn[$f_method]++
    request_method_size[$f_method]+= $f_size
  }
    
  if(count_proto==1) {    
    
    c_port="" ; c_proto=""
    cnt=split($f_url,t1,"://")
    if (cnt == 0 || $f_method == "CONNECT") {
	cnt2=split($f_url,t2,":")
	c_port=t2[2]
	port[c_port]++
    } else {
	c_proto=toupper(t1[1])
	proto[c_proto]++
    }
   
   }
    		       
    obj_uniq[ext]++
    
    if (status_cons[a1[1]]==consider_hit) {

	global_hit_size+= $f_size
    
	obj_hit_conn[ext]++
	obj_hit_size[ext]+= $f_size
	CountSize(consider_hit)
	
      if(count_proto ==1) {
	port_hit_conn[c_port]++
	port_hit_size[c_port]+= $f_size
	proto_hit_conn[c_proto]++
        proto_hit_size[c_proto]+= $f_size
      }
      
      if(count_hierarchy ==1) {
	peer_fetch_hit_conn["DIRECT"]++
	peer_fetch_hit_size["DIRECT"]+=$f_size
      }
	
	return

    } else {

	global_other_size+= $f_size
    
	if (status_cons[a1[1]]==consider_miss) {
    	    
	    obj_miss_conn[ext]++
	    obj_miss_size[ext]+= $f_size
	    CountSize(consider_miss)
    
          if(count_proto ==1) {	    
            port_miss_conn[c_port]++
    	    port_miss_size[c_port]+= $f_size
	    proto_miss_conn[c_proto]++
	    proto_miss_size[c_proto]+= $f_size
	  }
	  
	    CountPeer(consider_miss)
	    return
	
	} else {
	    
	    if (status_cons[a1[1]]==consider_deny) {
    	      if(count_proto ==1) {
        	port_deny_conn[c_port]++
		port_deny_size[c_port]+= $f_size
		proto_deny_conn[c_proto]++
		proto_deny_size[c_proto]+= $f_size
	      }	
		CountPeer(consider_deny)
		
		if(count_methods==1) {
		    request_method_deny_conn[$f_method]++
		    request_method_deny_size[$f_method]+= $f_size
		}
			  
		return
	    }
	}
    }
}


function CountSize(by_status) { ###############################################

    if(count_obj_size !=1) {return}

    i=1
    while (i<=size_scale_max) {
	if ($f_size < size_scale[i]) {
	    size_array_conn[i,by_status]++
	    size_array_size[i,by_status]+=$f_size
	    return
	}
	i++    
    }
    
    size_array_conn[size_scale_max+1,by_status]++
    size_array_size[size_scale_max+1,by_status]+=$f_size
}



function ShowProgress() { #####################################################

    if (progress_update==0) {; return 0}
    
    progress_count++
    if (progress_count > progress_update) {
	progress_count = 1
	print sprintf ("%9.0f",NR-1) " Lines Processed, " \
	      "In:" VeryShortDigit(global_other_size,"Bytes") ", Out:"\
	      VeryShortDigit(global_other_size+global_hit_size,"Bytes") \
	      ", Hit Ratio:" \
	      sprintf("%6.2f",global_hit_size/(global_other_size+global_hit_size)*100) " %    " \
	      "\x01b[1A\x01b[80D"
    }
}


function FixStart() { ########################################################
    if(count_elapsed==1) {start_time=systime()}
}

function ShortDigit(inNum,conv_mode) { #######################################

    if (conv_mode=="Bytes") {
	dv=1024 ;sfx1="B"; sfx2=" "; sfx3="  B" ; pat="%8.3f" } else {
	dv=1000 ;sfx1="" ; sfx2="" ; sfx3=" "  ; pat="%8.3f"  } 
    
    wm=1000

    if (inNum<wm) {r=sprintf("%8.0f",inNum); return r sfx3}
    if (inNum<wm^2) {r=sprintf(pat,inNum/dv) sfx2 "K" sfx1 ; return r}
    if (inNum<wm^3) {r=sprintf(pat,inNum/dv^2) sfx2 "M" sfx1 ; return r}
    if (inNum<wm^4) {r=sprintf(pat,inNum/dv^3) sfx2 "G" sfx1 ; return r}
    if (inNum<wm^5) {r=sprintf(pat,inNum/dv^4) sfx2 "T" sfx1 ; return r}
}


function VeryShortDigit(inNum,conv_mode) { ###################################

    if (conv_mode=="Bytes") {
        dv=1024 ;sfx1="B"; sfx3="B"  ; pat="%5.1f" } else {
        dv=1000 ;sfx1="" ; sfx3=" "  ; pat="%5.1f" }

    mdx[1]=""
    mdx[2]="K"
    mdx[3]="M"
    mdx[4]="G"
    mdx[5]="T"
	
    if (inNum<dv) {r=sprintf("%3.f",inNum);    md=1} else {
    if (inNum<dv^2) {r=sprintf(pat,inNum/dv);  md=2} else {
    if (inNum<dv^3) {r=sprintf(pat,inNum/dv^2);md=3} else {
    if (inNum<dv^4) {r=sprintf(pat,inNum/dv^3);md=4} else {
    if (inNum<dv^5) {r=sprintf(pat,inNum/dv^4);md=5}}}}}

    if (length(r)>5 && conv_mode=="Bytes") {
	r1 = r/dv
	r2 = sprintf(pat,r1)
	md++
	vsd= r2 mdx[md] sfx1
	return vsd
    
    } else {

        if (md==1) {vsd= "  " r sfx3; return vsd} else {
		    vsd= r mdx[md] sfx1; return vsd    }
		
    }

}
					    

function GetExt(url) { #######################################################
    
    q = "[?]|%3[fF]|@|;|&"
    if (url ~ q) { return "<QUERY>" }
    
    x1=split(url,AR1,"/")
    
    if (index(AR1[x1],".")>0) {
	n=split(AR1[x1],a2,".")
	if (length(a2[n])>6) {return "<LONG.>"}
	return tolower(a2[n])
    } else { return "/" }
}


function DoNumSort(in_array,total_rec,second_dims,sort_by) { #################

    complete_flag=0
    while (complete_flag != 1) {
        i1=1
        complete_flag=1
        while (i1<=total_rec) {
            if (in_array[i1,sort_by] < in_array[i1+1,sort_by]) {
                j1=1
                while (j1<=second_dims) {
                    temp[j1]=in_array[i1,j1]
                    in_array[i1,j1]=in_array[i1+1,j1]
                    in_array[i1+1,j1]=temp[j1]
                    j1++
                }
                complete_flag=0
            }
	    i1++
        }
    }
}

function PrintTitle(title) { ###################################################

    printf "\n" vhl_on[v] "\n~~~ " title " "
    ln1=74-length(title); x9=1
    while (x9<=ln1) {printf "~"; x9++}
    printf "\n" vhl_off[v] "\n"
}


function UTC(ts,in_utc) { ###############################################################

    in_utc=in_utc + (time_offset+1)*3600    
    ts[1] = in_utc % 60
    tm1   = int(in_utc/60)
    ts[2] = tm1 % 60
    tm2   = int(tm1/60)
    ts[3] = tm2 % 24
    tm3   = int(tm2/24)
    tm4   = int(tm3/1461)
    tm5   = int(((tm3 % 1461)-1)/365)
    ts[6] = 1970+tm4*4+tm5
    ydays = tm3-tm4*1461-tm5*365+1
    if(tm5==2) {mt[3]=29} else {mt[3]=28} #mar
    
    xi=ydays; xj=0
    while(xi>0) {
	xj++
	xi=xi-mt[xj]
	if(xi<=0) {
	    ts[5]=xj
	    ts[4]=xi+mt[xj-1]
	    return
	}
    }

    ts[5]=12
    ts[4]=xi+mt[12]
    return    
}


function UTCshort(ts) { ##########################################################

    utc_ts=int($f_ts)    

    if(use_extended !=1) {
	tm1   = utc_ts + (time_offset+1)*3600
	tm2   = int(tm1/3600)
	ts[3] = tm2 % 24
	tm3   = int(tm2/24)
	tm4   = int(tm3/1461)
	tm5   = int(((tm3 % 1461)-1)/365)
	ts[7] = tm3-tm4*1461-tm5*365+1
	return
    
    } else {
    
	ts[3] = sprintf("%d",strftime("%H",utc_ts))
	ts[7] = sprintf("%d",strftime("%j",utc_ts))
	return
    }
}