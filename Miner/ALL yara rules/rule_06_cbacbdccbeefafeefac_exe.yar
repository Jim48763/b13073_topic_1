rule cbacbdccbeefafeefac_exe {
strings:
        $s1 = "WinSearchChildren"
        $s2 = "SW_SHOWNOACTIVATE"
        $s3 = "GUICTRLSETGRAPHIC"
        $s4 = "UnloadUserProfile"
        $s5 = "msctls_progress32"
        $s6 = "SetDefaultDllDirectories"
        $s7 = "AUTOITCALLVARIABLE%d"
        $s8 = "msctls_statusbar321"
        $s9 = "GUICTRLCREATECONTEXTMENU"
        $s10 = "Runtime Error!"
        $s11 = "IcmpCreateFile"
        $s12 = "<\"t|<%tx<'tt<$tp<&tl<!th<otd<]t`<[t\\<\\tX<"
        $s13 = "CoCreateInstanceEx"
        $s14 = "OpenWindowStationW"
        $s15 = "EWM_GETCONTROLNAME"
        $s16 = "SOUNDSETWAVEVOLUME"
        $s17 = "~f;D$@ulIyt"
        $s18 = "Run Script:"
        $s19 = "\"Rg,wdf6IM"
        $s20 = ">Ctu^e{1_WP"
condition:
    uint16(0) == 0x5a4d and filesize < 6295KB and
    4 of them
}
    
