rule Locky_exe {
strings:
        $s1 = "GarrisonsNematode"
        $s2 = "GetKeyboardLayout"
        $s3 = "IntenseFigurehead"
        $s4 = "MagnetisationInterfacing"
        $s5 = "InstillsImprovements"
        $s6 = "MeltedFundamentalism"
        $s7 = "OutclassedGreengages"
        $s8 = "FilletModernisation"
        $s9 = "OptimistMarginality"
        $s10 = "IntimatesInterplays"
        $s11 = "NonparticipationFreezer"
        $s12 = "RegSetValueExA"
        $s13 = "JabInterviewed"
        $s14 = "FixingMortices"
        $s15 = "MercenariesInfinitesimals"
        $s16 = "OutlayIntercountry"
        $s17 = "MetaboliseMuscadel"
        $s18 = "InsurgentFireguard"
        $s19 = "OralNovices"
        $s20 = "ProductName"
condition:
    uint16(0) == 0x5a4d and filesize < 185KB and
    4 of them
}
    
