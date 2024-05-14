rule aaadeafdaaaafcebeeffcbcdba_exe {
strings:
        $s1 = "WinSearchChildren"
        $s2 = "msctls_progress32"
        $s3 = "SetUserObjectSecurity"
        $s4 = "SetDefaultDllDirectories"
        $s5 = "AUTOITCALLVARIABLE%d"
        $s6 = "msctls_statusbar321"
        $s7 = "GUICTRLCREATECONTEXTMENU"
        $s8 = "Runtime Error!"
        $s9 = "IcmpCreateFile"
        $s10 = "<\"t|<%tx<'tt<$tp<&tl<!th<otd<]t`<[t\\<\\tX<"
        $s11 = "EWM_GETCONTROLNAME"
        $s12 = "STARTMENUCOMMONDIR"
        $s13 = "SOUNDSETWAVEVOLUME"
        $s14 = "OpenWindowStationW"
        $s15 = "CopyFileExW"
        $s16 = "LoadStringW"
        $s17 = "~f;D$@ulIyt"
        $s18 = "</security>"
        $s19 = "Run Script:"
        $s20 = "Old_Persian"
condition:
    uint16(0) == 0x5a4d and filesize < 1003KB and
    4 of them
}
    
