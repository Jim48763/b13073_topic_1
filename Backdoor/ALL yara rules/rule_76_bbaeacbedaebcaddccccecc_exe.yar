rule bbaeacbedaebcaddccccecc_exe {
strings:
        $s1 = "BitConvertBuilder"
        $s2 = "ES_DISPLAY_REQUIRED"
        $s3 = "EnterDebugMode"
        $s4 = "GetProcessesByName"
        $s5 = "RuntimuFieldHandlu"
        $s6 = "CallingCo~ventions"
        $s7 = "Comf{sibleA"
        $s8 = "My.Computer"
        $s9 = "_^o}DwlXatn"
        $s10 = "_CorExe]ain"
        $s11 = "System.Li~q"
        $s12 = ">NET Framew"
        $s13 = "ProductName"
        $s14 = "PixelFormat"
        $s15 = "SocketFlags"
        $s16 = "VarFileInfo"
        $s17 = "ComputeXash"
        $s18 = "~t|megypxHa"
        $s19 = "}~czrpe9dwl"
        $s20 = "L?xml versi"
condition:
    uint16(0) == 0x5a4d and filesize < 195KB and
    4 of them
}
    
