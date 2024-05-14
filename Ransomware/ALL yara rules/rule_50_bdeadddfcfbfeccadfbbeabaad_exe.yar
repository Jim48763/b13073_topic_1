rule bdeadddfcfbfeccadfbbeabaad_exe {
strings:
        $s1 = "TRttiManagedField"
        $s2 = "ToShortUTF8String"
        $s3 = "TCustomAttribute|"
        $s4 = "StaticSynchronize"
        $s5 = "Argument out of range"
        $s6 = "GetImplementedInterfaces"
        $s7 = "93EFCA2C47B940A9AA875C7952"
        $s8 = "432CDE87A9E741CFA298A8"
        $s9 = "Protocol not available"
        $s10 = "CD8E617A747E63FA0114D8277A7014"
        $s11 = "Without SSL support"
        $s12 = "RecvTerminated"
        $s13 = "FOrphanPackage"
        $s14 = "Winapi.ActiveX"
        $s15 = "TotalElementCount`"
        $s16 = "GetConsoleOutputCP"
        $s17 = "CoCreateInstanceEx"
        $s18 = "System.AnsiStrings"
        $s19 = "QualifiedClassName"
        $s20 = "TRttiRecordMethod8"
condition:
    uint16(0) == 0x5a4d and filesize < 1211KB and
    4 of them
}
    
