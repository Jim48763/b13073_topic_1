rule fcdaebcdbcfcedfcbdbfffff_exe {
strings:
        $s1 = "SetDefaultDllDirectories"
        $s2 = "      version=\"6.0.0.0\""
        $s3 = "RegSetValueExW"
        $s4 = "LoadStringW"
        $s5 = "\"BQ2v?`fka"
        $s6 = "#4,v=s|L(G6"
        $s7 = "bf@kcMDeN%/"
        $s8 = "RcH15NoM4PW"
        $s9 = "&oq(%7,8hcF"
        $s10 = ".M%rVZd^*P9"
        $s11 = "DOU}QFK@V_B"
        $s12 = "DialogBoxParamW"
        $s13 = "ProgramFilesDir"
        $s14 = "`local vftable'"
        $s15 = "IsWindowVisible"
        $s16 = "DeviceIoControl"
        $s17 = "ARarHtmlClassName"
        $s18 = "WindowsCodecs.dll"
        $s19 = "Not enough memory"
        $s20 = "SetThreadPriority"
condition:
    uint16(0) == 0x5a4d and filesize < 4306KB and
    4 of them
}
    
