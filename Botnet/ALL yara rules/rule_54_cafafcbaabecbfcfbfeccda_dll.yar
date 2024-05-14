rule cafafcbaabecbfcfbfeccda_dll {
strings:
        $s1 = "CoRegisterMessageFilter"
        $s2 = "VerInstallFileA"
        $s3 = "winspool.drv"
        $s4 = "dwOKSubclass"
        $s5 = "SymUnDName64"
        $s6 = "CreateToolbarEx"
        $s7 = "GetStretchBltMode"
        $s8 = "CallMsgFilter"
        $s9 = "VirtualProtect"
        $s10 = "GetCurrentThread"
        $s11 = "version.dll"
        $s12 = "wid32Message"
        $s13 = "    <security>"
        $s14 = "GetProcAddress"
        $s15 = "RegSetValueW"
        $s16 = "imagehlp.dll"
        $s17 = "VirtualAlloc"
        $s18 = "AlphaBlend"
        $s19 = "msimg32.dll"
        $s20 = "LoadLibraryA"
condition:
    uint16(0) == 0x5a4d and filesize < 539KB and
    4 of them
}
    
