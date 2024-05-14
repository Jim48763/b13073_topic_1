rule aecacdfbdaaaaddedac_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "More information at:"
        $s3 = "RegSetValueExW"
        $s4 = "iNnprk3:-,l"
        $s5 = "VarFileInfo"
        $s6 = "`z]bf~82y'+"
        $s7 = "DialogBoxParamW"
        $s8 = "FileDescription"
        $s9 = "HKEY_CLASSES_ROOT"
        $s10 = "Delete: DeleteFile(\"%s\")"
        $s11 = "DispatchMessageW"
        $s12 = "GetModuleHandleW"
        $s13 = "ImageList_Create"
        $s14 = "SHBrowseForFolderW"
        $s15 = "ki.7HFox\\Gm"
        $s16 = "EnableWindow"
        $s17 = "GetTickCount"
        $s18 = "RegEnumValueW"
        $s19 = "SysListView32"
        $s20 = "U>DFH3//f\\'!"
condition:
    uint16(0) == 0x5a4d and filesize < 1200KB and
    4 of them
}
    
