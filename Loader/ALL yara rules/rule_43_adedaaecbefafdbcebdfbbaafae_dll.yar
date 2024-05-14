rule adedaaecbefafdbcebdfbbaafae_dll {
strings:
        $s1 = "DefMenuItemHeight"
        $s2 = "EnableImageDevice"
        $s3 = "GetEnvironmentStrings"
        $s4 = "Unable to insert an item"
        $s5 = "\\'\\'%s\\'\\' is not a valid time"
        $s6 = "Generics.Collections"
        $s7 = "bsieSemiTransparent"
        $s8 = "GeTBod]aeFaaeN)beA"
        $s9 = "GetConsoleOutputCP"
        $s10 = "ProductName"
        $s11 = "bsipDefault"
        $s12 = "LoadStringW"
        $s13 = "VarFileInfo"
        $s14 = ".bsTrayIcon"
        $s15 = "clBtnShadow"
        $s16 = "dbszlibcompress"
        $s17 = "DeviceIoControl"
        $s18 = "TbsSkinComboBox"
        $s19 = "QueryDosDeviceW"
        $s20 = "FileDescription"
condition:
    uint16(0) == 0x5a4d and filesize < 588KB and
    4 of them
}
    
