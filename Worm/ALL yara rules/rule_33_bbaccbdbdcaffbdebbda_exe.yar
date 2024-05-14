rule bbaccbdbdcaffbdebbda_exe {
strings:
        $s1 = "meQueryDosDeviceW"
        $s2 = "](wlb=LM%<k"
        $s3 = "aBm*IS0U6A'"
        $s4 = "tALocalFileTimeToFileTime"
        $s5 = "x^ZVmN,}\\L"
        $s6 = "KERNEL32.dll"
        $s7 = "FatalAppExitW"
        $s8 = "BuildCommDCBW"
        $s9 = "eaWriteFileEx"
        $s10 = "GetGeoInfoW"
        $s11 = "nalstrcmp"
        $s12 = "Y(yn\\O@S"
        $s13 = "\\\")8KwY"
        $s14 = "(\\n%@)\""
        $s15 = "|gK{<dw&"
        $s16 = "PV^'L=-N"
        $s17 = "_)#[P h5"
        $s18 = "PFs=6)MW"
        $s19 = "=7%<\"_:"
        $s20 = "6kT:@q-L"
condition:
    uint16(0) == 0x5a4d and filesize < 81KB and
    4 of them
}
    
