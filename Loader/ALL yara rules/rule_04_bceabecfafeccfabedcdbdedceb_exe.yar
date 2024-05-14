rule bceabecfafeccfabedcdbdedceb_exe {
strings:
        $s1 = "SetDefaultDllDirectories"
        $s2 = "LoadStringA"
        $s3 = "DialogBoxParamA"
        $s4 = "TerminateProcess"
        $s5 = "SetFilePointerEx"
        $s6 = "ImageList_Create"
        $s7 = "DispatchMessageA"
        $s8 = "SetThreadStackGuarantee"
        $s9 = "OovP:OpayluD"
        $s10 = "&Small Icons"
        $s11 = "UpdateWindow"
        $s12 = "SysListView32"
        $s13 = "RtlCaptureContext"
        $s14 = "LoadLibraryExW"
        $s15 = "CorExitProcess"
        $s16 = "    </security>"
        $s17 = "DeleteCriticalSection"
        $s18 = "GetSystemTimeAsFileTime"
        $s19 = "OOO Inversum0"
        $s20 = "About Controls"
condition:
    uint16(0) == 0x5a4d and filesize < 511KB and
    4 of them
}
    
