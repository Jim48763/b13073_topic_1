rule faafdcfecdfecbaddedacccdfffbb_exe {
strings:
        $s1 = "SW_SHOWNOACTIVATE"
        $s2 = "msctls_progress32"
        $s3 = "GUICTRLSETGRAPHIC"
        $s4 = "WinSearchChildren"
        $s5 = "CreateThreadpoolTimer"
        $s6 = "SetUserObjectSecurity"
        $s7 = "`vector destructor iterator'"
        $s8 = "SetDefaultDllDirectories"
        $s9 = "AUTOITCALLVARIABLE%d"
        $s10 = "msctls_statusbar321"
        $s11 = "GUICTRLCREATECONTEXTMENU"
        $s12 = "VirtualAllocEx"
        $s13 = "RegSetValueExW"
        $s14 = "IcmpCreateFile"
        $s15 = "<\"t|<%tx<'tt<$tp<&tl<!th<otd<]t`<[t\\<\\tX<"
        $s16 = "uiAccess=\"false\""
        $s17 = "CoCreateInstanceEx"
        $s18 = "OpenWindowStationW"
        $s19 = "SOUNDSETWAVEVOLUME"
        $s20 = "EWM_GETCONTROLNAME"
condition:
    uint16(0) == 0x5a4d and filesize < 861KB and
    4 of them
}
    
