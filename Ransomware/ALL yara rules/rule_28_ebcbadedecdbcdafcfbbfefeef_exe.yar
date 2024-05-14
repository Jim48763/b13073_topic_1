rule ebcbadedecdbcdafcfbbfefeef_exe {
strings:
        $s1 = "SetDefaultDllDirectories"
        $s2 = ":$:,:4:<:D:L:T:\\:d:l:t:|: ;$;4;8;@;X;h;l;|;"
        $s3 = "XOt2w{bHpIj"
        $s4 = "F#z7bOi%hLU"
        $s5 = "FoldStringW"
        $s6 = "w*#.$`80:ej"
        $s7 = "H5-6li\"Amc"
        $s8 = "+^CNQ-v)4*&"
        $s9 = "o<,t/G.iL;I"
        $s10 = "`local vftable'"
        $s11 = "DeviceIoControl"
        $s12 = "ProgramFilesDir"
        $s13 = "IsWindowVisible"
        $s14 = "DialogBoxParamW"
        $s15 = "WindowsCodecs.dll"
        $s16 = "SetThreadPriority"
        $s17 = "Not enough memory"
        $s18 = "ARarHtmlClassName"
        $s19 = "GetModuleHandleW"
        $s20 = "DispatchMessageW"
condition:
    uint16(0) == 0x5a4d and filesize < 2511KB and
    4 of them
}
    
