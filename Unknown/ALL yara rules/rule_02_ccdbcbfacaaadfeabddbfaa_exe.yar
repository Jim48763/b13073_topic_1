rule ccdbcbfacaaadfeabddbfaa_exe {
strings:
        $s1 = "Msctls_Progress32"
        $s2 = "WinSearchChildren"
        $s3 = "UnloadUserProfile"
        $s4 = "SetUserObjectSecurity"
        $s5 = "CreateThreadpoolTimer"
        $s6 = "`vector destructor iterator'"
        $s7 = "SetDefaultDllDirectories"
        $s8 = "AUTOITCALLVARIABLE%d"
        $s9 = "msctls_statusbar321"
        $s10 = "GUICTRLCREATECONTEXTMENU"
        $s11 = "IcmpCreateFile"
        $s12 = "Runtime Error!"
        $s13 = "<\"t|<%tx<'tt<$tp<&tl<!th<otd<]t`<[t\\<\\tX<"
        $s14 = "STARTMENUCOMMONDIR"
        $s15 = "EWM_GETCONTROLNAME"
        $s16 = "SOUNDSETWAVEVOLUME"
        $s17 = "LoadStringW"
        $s18 = "CopyFileExW"
        $s19 = "Old_Persian"
        $s20 = "$.ZVu=?QB[P"
condition:
    uint16(0) == 0x5a4d and filesize < 945KB and
    4 of them
}
    
