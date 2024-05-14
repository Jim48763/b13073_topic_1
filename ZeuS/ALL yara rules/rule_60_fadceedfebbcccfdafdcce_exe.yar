rule fadceedfebbcccfdafdcce_exe {
strings:
        $s1 = "Care375bema3759to"
        $s2 = "?FreeTimerAXJDI"
        $s3 = "?AppNameExPAFPAFG"
        $s4 = "?AddFolderExDPAD"
        $s5 = "Rale9adssin83ate"
        $s6 = "?AddClassOldHPAEHPAK"
        $s7 = "?ValidateDateExWDEE"
        $s8 = "Ox6boat73709"
        $s9 = "Bask615hidti"
        $s10 = "?PutDateNewPAKPAJPAJN"
        $s11 = "?IsNotPathWHI"
        $s12 = "?HideKeyNameNewXK"
        $s13 = "?FindWidthAEDE"
        $s14 = "?GetAppNameGHHFN"
        $s15 = "?FindPenWPANPAJPAFE"
        $s16 = "compression init"
        $s17 = "GetProcessHeap"
        $s18 = "?TextOldJM"
        $s19 = "PathIsUNCA"
        $s20 = "?AddTimeExAIPAIEI"
condition:
    uint16(0) == 0x5a4d and filesize < 169KB and
    4 of them
}
    
