rule baaaeabdaebeceebaedfbc_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "ProductName"
        $s5 = ")7`SvJ1+yQC"
        $s6 = "%.R=vX2d!bF"
        $s7 = "VarFileInfo"
        $s8 = "Us6h(]PDK|A"
        $s9 = "FileDescription"
        $s10 = "DialogBoxParamA"
        $s11 = "GetShortPathNameA"
        $s12 = "RemoveDirectoryA"
        $s13 = "DispatchMessageA"
        $s14 = "GetModuleHandleA"
        $s15 = "SHBrowseForFolderA"
        $s16 = "EnableWindow"
        $s17 = "GetTickCount"
        $s18 = "RegEnumValueA"
        $s19 = "IIDFromString"
        $s20 = "SysListView32"
condition:
    uint16(0) == 0x5a4d and filesize < 241KB and
    4 of them
}
    
