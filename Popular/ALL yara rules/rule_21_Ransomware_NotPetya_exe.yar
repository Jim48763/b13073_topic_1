rule Ransomware_NotPetya_exe {
strings:
        $s1 = "@\\perfc.dat"
        $s2 = "\\rundll32.exe"
        $s3 = "    </security>"
        $s4 = "IYZ/[JLu`a"
        $s5 = "e`+DbVHs*."
        $s6 = "Washington1"
        $s7 = "ExitProcess"
        $s8 = "JRN}jN|x>|c8"
        $s9 = "KERNEL32.dll"
        $s10 = "%6RWWXa P]]^"
        $s11 = "100427180659Z0#"
        $s12 = "CreateProcessW"
        $s13 = "N<v]zo<n?M"
        $s14 = "3\\.c,naL'"
        $s15 = "rt\\=4v?*["
        $s16 = "pi`'irQfB_"
        $s17 = "z'VIBk\\m."
        $s18 = "(?'`ipfQri"
        $s19 = "USER32.dll"
        $s20 = "b''Lv\\^]3d"
condition:
    uint16(0) == 0x5a4d and filesize < 371KB and
    4 of them
}
    
