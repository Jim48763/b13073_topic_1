rule aeddeeeccddfecdaeffdffddacd_exe {
strings:
        $s1 = "RuntimuFieldHandlu"
        $s2 = "CallingCo~ventions"
        $s3 = "Comf{sibleA"
        $s4 = "_^o}DwlXatn"
        $s5 = "op_Equality"
        $s6 = "_CorExe]ain"
        $s7 = "System.Li~q"
        $s8 = ">NET Framew"
        $s9 = "ProductName"
        $s10 = "VarFileInfo"
        $s11 = "ComputeXash"
        $s12 = "~t|megypxHa"
        $s13 = "}~czrpe9dwl"
        $s14 = "L?xml versi"
        $s15 = "FileDescription"
        $s16 = "MessageBoxRuttons"
        $s17 = "set_RedirestStandardE"
        $s18 = "Microsoft0Corporatio~"
        $s19 = "gut_FileName"
        $s20 = "Synchronized"
condition:
    uint16(0) == 0x5a4d and filesize < 320KB and
    4 of them
}
    
