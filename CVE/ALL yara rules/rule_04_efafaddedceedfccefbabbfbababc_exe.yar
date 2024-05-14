rule efafaddedceedfccefbabbfbababc_exe {
strings:
        $s1 = "CreateWindowStationW"
        $s2 = "CorExitPrTB."
        $s3 = "EnumDeviceDrivers"
        $s4 = "VirtualProtect"
        $s5 = "HPDispEchT"
        $s6 = "DMec7 ]YO3"
        $s7 = "5La0GoT;OC"
        $s8 = "ExitProcess"
        $s9 = "</assembly>"
        $s10 = "    <security>"
        $s11 = "GetProcAddress"
        $s12 = "GetValueS~"
        $s13 = "Q`/?_e+[T?"
        $s14 = "SHELL32.dll"
        $s15 = "CreateBitmap"
        $s16 = "LoadLibraryA"
        $s17 = "dStackGuara"
        $s18 = "KERNEL32.DLL"
        $s19 = "(e+0001#SNAN"
        $s20 = "poolTimerm"
condition:
    uint16(0) == 0x5a4d and filesize < 44KB and
    4 of them
}
    
