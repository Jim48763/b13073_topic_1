rule ecfbffbfeccefaeadfdfdaffccab_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "spanish-guatemala"
        $s3 = "Invalid filename."
        $s4 = "GetEnvironmentStrings"
        $s5 = "RegSetValueExA"
        $s6 = "SetConsoleCtrlHandler"
        $s7 = "http://www.rsdn.ru"
        $s8 = "GetWindowDC"
        $s9 = "Switzerland"
        $s10 = "Y>O%ALc7_[,"
        $s11 = "LC_MONETARY"
        $s12 = "ProductName"
        $s13 = "LoadStringA"
        $s14 = "VarFileInfo"
        $s15 = "FileDescription"
        $s16 = "GetThreadLocale"
        $s17 = ".?AVCClientDC@@"
        $s18 = "IsWindowVisible"
        $s19 = "english-jamaica"
        $s20 = "UnpackDDElParam"
condition:
    uint16(0) == 0x5a4d and filesize < 713KB and
    4 of them
}
    
