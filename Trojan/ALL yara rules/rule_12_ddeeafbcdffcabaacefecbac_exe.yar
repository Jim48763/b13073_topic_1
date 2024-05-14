rule ddeeafbcdffcabaacefecbac_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "More information at:"
        $s3 = "RegSetValueExA"
        $s4 = "Odi^4A(@N#."
        $s5 = "DialogBoxParamA"
        $s6 = "GetShortPathNameA"
        $s7 = "DispatchMessageA"
        $s8 = "GetModuleHandleA"
        $s9 = "SHBrowseForFolderA"
        $s10 = "EnableWindow"
        $s11 = "GetTickCount"
        $s12 = "RegEnumValueA"
        $s13 = "SysListView32"
        $s14 = "InvalidateRect"
        $s15 = "SHAutoComplete"
        $s16 = "CloseClipboard"
        $s17 = "LoadLibraryExA"
        $s18 = "RegCreateKeyExA"
        $s19 = "CoTaskMemFree"
        $s20 = "GetDeviceCaps"
condition:
    uint16(0) == 0x5a4d and filesize < 293KB and
    4 of them
}
    
