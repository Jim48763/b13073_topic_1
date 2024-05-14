rule ffaddfbcadcdfdbfeffafce_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "More information at:"
        $s3 = "RegSetValueExA"
        $s4 = "DialogBoxParamA"
        $s5 = "GetShortPathNameA"
        $s6 = "DispatchMessageA"
        $s7 = "GetModuleHandleA"
        $s8 = "SHBrowseForFolderA"
        $s9 = "EnableWindow"
        $s10 = "('r:Df}.GVfA"
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
    uint16(0) == 0x5a4d and filesize < 454KB and
    4 of them
}
    
