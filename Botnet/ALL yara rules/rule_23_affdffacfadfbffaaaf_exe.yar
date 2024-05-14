rule affdffacfadfbffaaaf_exe {
strings:
        $s1 = "GetWindowDC"
        $s2 = "DispatchMessageW"
        $s3 = "SHLWAPI.dll"
        $s4 = "KERNEL32.dll"
        $s5 = "GetClassNameW"
        $s6 = "GetProcAddress"
        $s7 = "DllRegisterServer"
        $s8 = "USER32.dll"
        $s9 = "GetBkColor"
        $s10 = "TN\\]U_$5b"
        $s11 = "MessageBoxA"
        $s12 = "LoadLibraryA"
        $s13 = "CreateFileW"
        $s14 = ".rdata$zzzdbg"
        $s15 = "SendMessageA"
        $s16 = "PluginInit"
        $s17 = "^_`5bFd,N"
        $s18 = "UAWAVVWSPH"
        $s19 = "8[]_^A\\A]A^A_"
        $s20 = "AWAVAUATVWUSH"
condition:
    uint16(0) == 0x5a4d and filesize < 43KB and
    4 of them
}
    
