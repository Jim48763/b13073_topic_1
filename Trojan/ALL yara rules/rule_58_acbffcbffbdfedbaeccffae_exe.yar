rule acbffcbffbdfedbaeccffae_exe {
strings:
        $s1 = "_Jv_RegisterClasses"
        $s2 = "GetModuleHandleA"
        $s3 = "__deregister_frame_info"
        $s4 = "EnterCriticalSection"
        $s5 = "libgcj-16.dll"
        $s6 = "VirtualProtect"
        $s7 = "0@.eh_fram"
        $s8 = "ExitProcess"
        $s9 = "KERNEL32.dll"
        $s10 = "VirtualQuery"
        $s11 = "FindNextFileA"
        $s12 = "__getmainargs"
        $s13 = "GetProcAddress"
        $s14 = "msvcrt.dll"
        $s15 = "TlsGetValue"
        $s16 = "CloseHandle"
        $s17 = "LoadLibraryA"
        $s18 = "CreateFileW"
        $s19 = "GetLastError"
        $s20 = "FreeLibrary"
condition:
    uint16(0) == 0x5a4d and filesize < 32KB and
    4 of them
}
    
