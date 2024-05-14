rule fcbddebfaafdeefcadaebcacab_exe {
strings:
        $s1 = "SetDefaultDllDirectories"
        $s2 = "RY5D[%\"-f>"
        $s3 = "FoldStringW"
        $s4 = "XsL\"!,3Ac@"
        $s5 = "hKZ!}t\"{SR"
        $s6 = "2(5cwO}Rs,8"
        $s7 = "Default.SFX"
        $s8 = "VarFileInfo"
        $s9 = "*i]SgL9NOHG"
        $s10 = "ProductName"
        $s11 = "FileDescription"
        $s12 = "`local vftable'"
        $s13 = "DeviceIoControl"
        $s14 = "ProgramFilesDir"
        $s15 = "IsWindowVisible"
        $s16 = "DialogBoxParamW"
        $s17 = "WindowsCodecs.dll"
        $s18 = "SetThreadPriority"
        $s19 = "Not enough memory"
        $s20 = "ARarHtmlClassName"
condition:
    uint16(0) == 0x5a4d and filesize < 2679KB and
    4 of them
}
    
