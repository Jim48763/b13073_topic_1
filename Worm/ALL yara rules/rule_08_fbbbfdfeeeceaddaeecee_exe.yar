rule fbbbfdfeeeceaddaeecee_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "RegSetValueExA"
        $s5 = "%UALKY3}O9C"
        $s6 = "DialogBoxParamA"
        $s7 = "GetShortPathNameA"
        $s8 = "RemoveDirectoryA"
        $s9 = "ImageList_Create"
        $s10 = "DispatchMessageA"
        $s11 = "GetModuleHandleA"
        $s12 = "SHBrowseForFolderA"
        $s13 = "EnableWindow"
        $s14 = "GetTickCount"
        $s15 = "RegEnumValueA"
        $s16 = "SysListView32"
        $s17 = "InvalidateRect"
        $s18 = "CloseClipboard"
        $s19 = "LoadLibraryExA"
        $s20 = "SHAutoComplete"
condition:
    uint16(0) == 0x5a4d and filesize < 239KB and
    4 of them
}
    
