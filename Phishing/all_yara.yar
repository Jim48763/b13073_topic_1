import pe
rule defdefadbacecbdbdccdcaaedafdd_exe {
strings:
        $s1 = ">616#6;6?vQl)hA\\"
        $s2 = "msctls_progress32"
        $s3 = "Uninitialized row"
        $s4 = "GetEnvironmentStrings"
        $s5 = "gamma table being rebuilt"
        $s6 = "invalid with alpha channel"
        $s7 = "Directory not empty"
        $s8 = "Runtime Error!"
        $s9 = "RegSetValueExA"
        $s10 = "invalid distance code"
        $s11 = "No child processes"
        $s12 = "invalid alpha mode"
        $s13 = "midiStreamProperty"
        $s14 = "KrAJip0XQge"
        $s15 = "4i5U6B738%9"
        $s16 = "J-aHU}/=p*^"
        $s17 = "J)27.^mK~u|"
        $s18 = "ProductName"
        $s19 = "dY%,c} C\"H"
        $s20 = "GetWindowDC"
condition:
    uint16(0) == 0x5a4d and filesize < 8025KB and
    4 of them
}
    