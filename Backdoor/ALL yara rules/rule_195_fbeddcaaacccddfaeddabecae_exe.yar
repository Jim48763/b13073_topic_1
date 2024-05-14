rule fbeddcaaacccddfaeddabecae_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "Dosya tablosu dolu."
        $s3 = "ProductName"
        $s4 = "a_*\"4oryAE"
        $s5 = "VarFileInfo"
        $s6 = "FileDescription"
        $s7 = "H::2UEE:UDD9TEE)SCC\"SED"
        $s8 = "tirilemedi.;Taray"
        $s9 = "Bu dosya bulunam"
        $s10 = "Temporary folder"
        $s11 = "Do you want to continue?"
        $s12 = "       <assemblyIdentity"
        $s13 = "Microsoft Corporation"
        $s14 = "\\JJX[IIdZJJQUEE&QBB"
        $s15 = "pINJJ<KP[Efk"
        $s16 = "Windows klas"
        $s17 = "       wextract.manifest"
        $s18 = " veya bozulmu"
        $s19 = "yor.$Bellek ay"
        $s20 = "Win32 Kabin Ay"
condition:
    uint16(0) == 0x5a4d and filesize < 188KB and
    4 of them
}
    
