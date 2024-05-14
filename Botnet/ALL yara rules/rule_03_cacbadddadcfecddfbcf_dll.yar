rule cacbadddadcfecddfbcf_dll {
strings:
        $s1 = "english-caribbean"
        $s2 = "k \"~12 e4 4 Wcga"
        $s3 = "eM\" 53dpT  ~ r1e"
        $s4 = "6gaP60t f sfL--sd"
        $s5 = "            <Install package=\"Package_"
        $s6 = "9y8edgs kPtxPde  4 dd3 "
        $s7 = "5e ao ee5Mo/xPde.~ <"
        $s8 = "SetupGetTargetPathW"
        $s9 = "rox6\"r  Sc\"cceelv"
        $s10 = "1 5i .9_48lp ?"
        $s11 = "invalid string position"
        $s12 = "SetConsoleCtrlHandler"
        $s13 = "ios_base::failbit set"
        $s14 = "GetConsoleOutputCP"
        $s15 = "LC_MONETARY"
        $s16 = "ProductName"
        $s17 = "2hXPGDL\"9e"
        $s18 = "\"6mrv=3~gP"
        $s19 = "k/cb-~350W "
        $s20 = "Xl_Jx~:w&-8"
condition:
    uint16(0) == 0x5a4d and filesize < 1905KB and
    4 of them
}
    
