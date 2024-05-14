rule dfececddffddaaeaecbf_exe {
strings:
        $s1 = "__CxxFrameHandler"
        $s2 = "GetEnvironmentStrings"
        $s3 = "RegSetValueExA"
        $s4 = "GetConsoleOutputCP"
        $s5 = "mKoSQnHypCM"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = ";*/4{U_dR9-"
        $s9 = "FileDescription"
        $s10 = "SetThreadPriority"
        $s11 = "C:\\PQGvQrHQ.exe"
        $s12 = "C:\\j7ket33L.exe"
        $s13 = "C:\\hyeF__9o.exe"
        $s14 = "C:\\663Jeo0t.exe"
        $s15 = "TerminateProcess"
        $s16 = "C:\\gWcGemcY.exe"
        $s17 = "C:\\1gJewhfJ.exe"
        $s18 = "C:\\yaDTQMxe.exe"
        $s19 = "C:\\YX8ej8w3.exe"
        $s20 = "C:\\fhvHfOIe.exe"
condition:
    uint16(0) == 0x5a4d and filesize < 522KB and
    4 of them
}
    
