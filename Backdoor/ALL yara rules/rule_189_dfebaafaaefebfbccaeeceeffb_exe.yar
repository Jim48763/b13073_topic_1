rule dfebaafaaefebfbccaeeceeffb_exe {
strings:
        $s1 = "PB_WindowID"
        $s2 = "GetShortPathNameA"
        $s3 = "DispatchMessageA"
        $s4 = "TerminateProcess"
        $s5 = "GetModuleHandleA"
        $s6 = "EnterCriticalSection"
        $s7 = "GetCurrentThreadId"
        $s8 = "EnableWindow"
        $s9 = "DefFrameProcA"
        $s10 = "PB_DropAccept"
        $s11 = "MDI_ChildClass"
        $s12 = "GetTempFileNameA"
        $s13 = "        version=\"6.0.0.0\""
        $s14 = "</assembly>PPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD"
        $s15 = "CoTaskMemFree"
        $s16 = "TranslateAcceleratorA"
        $s17 = "RegisterClassA"
        $s18 = "SizeofResource"
        $s19 = "GetCurrentProcess"
        $s20 = "SHBrowseForFolder"
condition:
    uint16(0) == 0x5a4d and filesize < 276KB and
    4 of them
}
    
