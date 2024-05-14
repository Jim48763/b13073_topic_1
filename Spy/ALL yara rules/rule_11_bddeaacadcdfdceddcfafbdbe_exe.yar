rule bddeaacadcdfdceddcfafbdbe_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "RegSetValueExA"
        $s5 = "IsWindowVisible"
        $s6 = "DialogBoxParamA"
        $s7 = "GetModuleHandleA"
        $s8 = "DispatchMessageA"
        $s9 = "SHBrowseForFolderA"
        $s10 = "EnableWindow"
        $s11 = "GetTickCount"
        $s12 = "SetWindowPos"
        $s13 = "RegEnumValueA"
        $s14 = "SysListView32"
        $s15 = "GetWindowRect"
        $s16 = "IIDFromString"
        $s17 = "CloseClipboard"
        $s18 = "InvalidateRect"
        $s19 = "SHAutoComplete"
        $s20 = "LoadLibraryExA"
condition:
    uint16(0) == 0x5a4d and filesize < 344KB and
    4 of them
}
    
