rule becbecfffdbefbb_exe {
strings:
        $s1 = "ProductName"
        $s2 = "VarFileInfo"
        $s3 = "FileDescription"
        $s4 = "    </security>"
        $s5 = "Google Inc."
        $s6 = "</assembly>"
        $s7 = "_XcptFilter"
        $s8 = "__getmainargs"
        $s9 = "LegalTrademark"
        $s10 = "Google Chrome"
        $s11 = "_controlfp"
        $s12 = "msvcrt.dll"
        $s13 = "VS_VERSION_INFO"
        $s14 = "FileVersion"
        $s15 = "Translation"
        $s16 = "CompanyName"
        $s17 = "OpenProcess"
        $s18 = "kernel32.dll"
        $s19 = "chrome.exe"
        $s20 = "70,0,3538,110"
condition:
    uint16(0) == 0x5a4d and filesize < 5512KB and
    4 of them
}
    
