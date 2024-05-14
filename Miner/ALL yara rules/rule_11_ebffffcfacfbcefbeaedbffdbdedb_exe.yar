rule ebffffcfacfbcefbeaedbffdbdedb_exe {
strings:
        $s1 = "&submit=Submit%21"
        $s2 = "Take away all engines."
        $s3 = "OI*N|\\<Z0u\"z"
        $s4 = " khBfF;)q-i"
        $s5 = "EncryptFile"
        $s6 = "3K}\"FGk%Yf"
        $s7 = "g\"(7A0jDnd"
        $s8 = "aE\"9+bB:=}"
        $s9 = "./`x^MoPf'z"
        $s10 = "MSComctlLib"
        $s11 = "]2T\"wP&)+o"
        $s12 = "VarFileInfo"
        $s13 = "V>bq05Iu*t_"
        $s14 = "\"=]Eb!*If%"
        $s15 = "#)AmI=BF'DY"
        $s16 = "Your Email."
        $s17 = "i2+]uz)f~DR"
        $s18 = "GetShortPathNameA"
        $s19 = "GetModuleHandleA"
        $s20 = "Procentage Done:"
condition:
    uint16(0) == 0x5a4d and filesize < 2310KB and
    4 of them
}
    
