rule cfbbdceabafbafdebbccbaffccabea_exe {
strings:
        $s1 = "msctls_trackbar32"
        $s2 = "msctls_progress32"
        $s3 = "WinSearchChildren"
        $s4 = "SetDefaultDllDirectories"
        $s5 = "AUTOITCALLVARIABLE%d"
        $s6 = "GUICTRLCREATECONTEXTMENU"
        $s7 = "IcmpCreateFile"
        $s8 = "RegSetValueExW"
        $s9 = "<\"t|<%tx<'tt<$tp<&tl<!th<otd<]t`<[t\\<\\tX<"
        $s10 = "CoCreateInstanceEx"
        $s11 = "OpenWindowStationW"
        $s12 = "SOUNDSETWAVEVOLUME"
        $s13 = "EWM_GETCONTROLNAME"
        $s14 = "STARTMENUCOMMONDIR"
        $s15 = "GetWindowDC"
        $s16 = "LoadStringW"
        $s17 = "VB1@}~G:n*M"
        $s18 = "~f;D$@ulIyt"
        $s19 = "CopyFileExW"
        $s20 = ",[HhS.-j'Lb"
condition:
    uint16(0) == 0x5a4d and filesize < 2810KB and
    4 of them
}
    
