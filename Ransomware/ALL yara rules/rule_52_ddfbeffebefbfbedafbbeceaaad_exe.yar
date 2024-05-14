rule ddfbeffebefbfbedafbbeceaaad_exe {
strings:
        $s1 = "TRttiManagedField"
        $s2 = "ToShortUTF8String"
        $s3 = "TCustomAttribute|"
        $s4 = "StaticSynchronize"
        $s5 = "Argument out of range"
        $s6 = "GetImplementedInterfaces"
        $s7 = "406A31EC0E5F12CD15F3"
        $s8 = "Protocol not available"
        $s9 = "Without SSL support"
        $s10 = "RecvTerminated"
        $s11 = "FOrphanPackage"
        $s12 = "Winapi.ActiveX"
        $s13 = "TotalElementCount`"
        $s14 = "GetConsoleOutputCP"
        $s15 = "CoCreateInstanceEx"
        $s16 = "System.AnsiStrings"
        $s17 = "QualifiedClassName"
        $s18 = "TRttiRecordMethod8"
        $s19 = "mkOperatorOverload"
        $s20 = "[LDRIVES]= "
condition:
    uint16(0) == 0x5a4d and filesize < 1213KB and
    4 of them
}
    
