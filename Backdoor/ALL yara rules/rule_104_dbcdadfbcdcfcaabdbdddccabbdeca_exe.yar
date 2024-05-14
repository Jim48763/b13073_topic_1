rule dbcdadfbcdcfcaabdbdddccabbdeca_exe {
strings:
        $s1 = "SetDefaultDllDirectories"
        $s2 = "      version=\"6.0.0.0\""
        $s3 = "RegSetValueExW"
        $s4 = "~Mo[q?b;}cm"
        $s5 = "0~VR7\"${x|"
        $s6 = "LoadStringW"
        $s7 = "Wy7V%[FP\"k"
        $s8 = "lefjP4}r]o<"
        $s9 = "+N-A]Cf=a3U"
        $s10 = "H= @MrVvF3N"
        $s11 = "DialogBoxParamW"
        $s12 = "ProgramFilesDir"
        $s13 = "`local vftable'"
        $s14 = "IsWindowVisible"
        $s15 = "DeviceIoControl"
        $s16 = "ARarHtmlClassName"
        $s17 = "WindowsCodecs.dll"
        $s18 = "SetThreadPriority"
        $s19 = "DispatchMessageW"
        $s20 = "GetModuleHandleW"
condition:
    uint16(0) == 0x5a4d and filesize < 2167KB and
    4 of them
}
    
