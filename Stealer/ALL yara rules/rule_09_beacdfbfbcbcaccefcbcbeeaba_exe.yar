rule beacdfbfbcbcaccefcbcbeeaba_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "RegSetValueExA"
        $s5 = "DialogBoxParamA"
        $s6 = "GetShortPathNameA"
        $s7 = "DispatchMessageA"
        $s8 = "GetModuleHandleA"
        $s9 = "SHBrowseForFolderA"
        $s10 = "EnableWindow"
        $s11 = "GetTickCount"
        $s12 = "IIDFromString"
        $s13 = "RegEnumValueA"
        $s14 = "SysListView32"
        $s15 = "InvalidateRect"
        $s16 = "SHAutoComplete"
        $s17 = "CloseClipboard"
        $s18 = "LoadLibraryExA"
        $s19 = "RegCreateKeyExA"
        $s20 = "CoTaskMemFree"
condition:
    uint16(0) == 0x5a4d and filesize < 456KB and
    4 of them
}
    
