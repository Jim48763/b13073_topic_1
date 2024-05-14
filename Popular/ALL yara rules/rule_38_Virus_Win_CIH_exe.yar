rule Virus_Win_CIH_exe {
strings:
        $s1 = "3\\lkcX=\"JS-+"
        $s2 = "VarFileInfo"
        $s3 = "ProductName"
        $s4 = "Wv/rCu{KZI9"
        $s5 = "FileDescription"
        $s6 = "Microsoft Corporation"
        $s7 = "    </security>"
        $s8 = "OpenProcessToken"
        $s9 = "VirtualProtect"
        $s10 = "WiG{k#UxM1"
        $s11 = "_FOidToStr"
        $s12 = "]QageBox1Ug"
        $s13 = "ADVAPI32.dll"
        $s14 = "s program can"
        $s15 = "GetProcAddress"
        $s16 = "OriginalFilename"
        $s17 = "]}=%8d oB="
        $s18 = "VS_VERSION_INFO"
        $s19 = "Translation"
        $s20 = "CompanyName"
condition:
    uint16(0) == 0x5a4d and filesize < 30KB and
    4 of them
}
    
