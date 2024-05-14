rule ceedabbfefffacbeeafcadab_exe {
strings:
        $s1 = "could not create one way tunnel"
        $s2 = "Error on send new tunnel cmd"
        $s3 = " -v version show the version. "
        $s4 = " Eg: ./xxx -h -s ssocksd"
        $s5 = "Can Not Connect To %s!"
        $s6 = " -a about show the about pages"
        $s7 = "_Jv_RegisterClasses"
        $s8 = "WSAGetLastError"
        $s9 = "Not support  UDP?"
        $s10 = "GetModuleHandleA"
        $s11 = "__deregister_frame_info"
        $s12 = "EnterCriticalSection"
        $s13 = " -g connport set the connect port."
        $s14 = " following options:"
        $s15 = "gethostbyname"
        $s16 = "Error : bind port %d ."
        $s17 = "Server IP Address Error!"
        $s18 = "start listen port here"
        $s19 = "                http://rootkiter.com/EarthWrom/"
        $s20 = "libgcj-16.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 46KB and
    4 of them
}
    
