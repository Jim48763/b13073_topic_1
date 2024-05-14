rule afcabffdbdbdbfcfdecbac_exe {
strings:
        $s1 = "TRttiManagedField"
        $s2 = "ToShortUTF8String"
        $s3 = "TCustomAttribute|"
        $s4 = "StaticSynchronize"
        $s5 = "Argument out of range"
        $s6 = "GetImplementedInterfaces"
        $s7 = "DAE3AE5CFC29373DC95C6F8D86"
        $s8 = "B90EE10DC6466FEE7856B4BC49"
        $s9 = "8231057DA5ACDA43E2E4"
        $s10 = "Protocol not available"
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
    
