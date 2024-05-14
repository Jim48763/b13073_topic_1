rule Joke_SnowAtDestkop_exe {
strings:
        $s1 = "VarFileInfo"
        $s2 = "ProductName"
        $s3 = "IsWindowVisible"
        $s4 = "FileDescription"
        $s5 = "GetModuleHandleA"
        $s6 = "CreateCompatibleDC"
        $s7 = "EnableWindow"
        $s8 = "SysListView32"
        $s9 = "InvalidateRgn"
        $s10 = "WinSnow98.EXE"
        $s11 = "CheckMenuItem"
        $s12 = "S&nowflake"
        $s13 = "_XcptFilter"
        $s14 = "EnumWindows"
        $s15 = "DestroyIcon"
        $s16 = "KERNEL32.dll"
        $s17 = "_adjust_fdiv"
        $s18 = "COMCTL32.dll"
        $s19 = "GetClassNameA"
        $s20 = "__getmainargs"
condition:
    uint16(0) == 0x5a4d and filesize < 33KB and
    4 of them
}
    
