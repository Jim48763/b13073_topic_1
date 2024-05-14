rule bbceadabdbebfedadbcdcbfeccaa_exe {
strings:
        $s1 = "SetDefaultDllDirectories"
        $s2 = "http://ocsp.comodoca.com0"
        $s3 = "RY5D[%\"-f>"
        $s4 = "FoldStringW"
        $s5 = "XsL\"!,3Ac@"
        $s6 = "hKZ!}t\"{SR"
        $s7 = "2(5cwO}Rs,8"
        $s8 = "Default.SFX"
        $s9 = "VarFileInfo"
        $s10 = "\"T`bSP%& ,"
        $s11 = "*i]SgL9NOHG"
        $s12 = "ProductName"
        $s13 = "FileDescription"
        $s14 = "`local vftable'"
        $s15 = "DeviceIoControl"
        $s16 = "ProgramFilesDir"
        $s17 = "IsWindowVisible"
        $s18 = "DialogBoxParamW"
        $s19 = "WindowsCodecs.dll"
        $s20 = "SetThreadPriority"
condition:
    uint16(0) == 0x5a4d and filesize < 3060KB and
    4 of them
}
    
