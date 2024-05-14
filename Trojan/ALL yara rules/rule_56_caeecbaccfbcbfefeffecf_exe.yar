rule caeecbaccfbcbfefeffecf_exe {
strings:
        $s1 = "_Jv_RegisterClasses"
        $s2 = "0@.eh_framl"
        $s3 = "GetModuleHandleA"
        $s4 = "__deregister_frame_info"
        $s5 = "EnterCriticalSection"
        $s6 = "libgcj-16.dll"
        $s7 = "GetDriveTypeW"
        $s8 = "VirtualProtect"
        $s9 = "A:\\Windows"
        $s10 = "ExitProcess"
        $s11 = "KERNEL32.dll"
        $s12 = "VirtualQuery"
        $s13 = "$RECYCLE.BIN"
        $s14 = "FindNextFileA"
        $s15 = "ExitWindowsEx"
        $s16 = "__getmainargs"
        $s17 = "GetProcAddress"
        $s18 = "CreateProcessA"
        $s19 = "USER32.dll"
        $s20 = "msvcrt.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 29KB and
    4 of them
}
    
