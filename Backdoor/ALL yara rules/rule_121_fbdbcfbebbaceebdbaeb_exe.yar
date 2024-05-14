rule fbdbcfbebbaceebdbaeb_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "System.Data.Common"
        $s3 = "msClinicInfo_Click"
        $s4 = "STAThreadAttribute"
        $s5 = "get_Columns"
        $s6 = "ProductName"
        $s7 = "pictureBox2"
        $s8 = "W;-NH,c]Q>g"
        $s9 = "Cancel_40px"
        $s10 = "fK}U$/eG{4n"
        $s11 = "j9k?i2eoya<"
        $s12 = "_CorExeMain"
        $s13 = "VarFileInfo"
        $s14 = "2,w;#S/bi.D"
        $s15 = "a^L=s]dY7l."
        $s16 = "KTZ DCW;a8d"
        $s17 = "g]C}Z:Q{-1n"
        $s18 = "3sZ =q(oa8|"
        $s19 = "Nza|`!J3BPr"
        $s20 = "/DZ 4+X3a8W"
condition:
    uint16(0) == 0x5a4d and filesize < 3738KB and
    4 of them
}
    
