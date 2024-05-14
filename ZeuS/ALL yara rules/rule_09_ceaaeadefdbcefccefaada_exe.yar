rule ceaaeadefdbcefccefaada_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "OleLoadFromStream"
        $s3 = "FreeUserPhysicalPages"
        $s4 = "CoAddRefServerProcess"
        $s5 = "GetFileAttributesExA"
        $s6 = "OpenWindowStationW"
        $s7 = "aULcn_`vo?D"
        $s8 = "kW>m-3niq8%"
        $s9 = "K(I0Hhf:ai!"
        $s10 = "+g0m)J61#P,"
        $s11 = "RKc,`o_'b3t"
        $s12 = "DtM96mI(EeR"
        $s13 = "DialogBoxParamW"
        $s14 = "ft!XncTdTnLang)"
        $s15 = "GetThreadLocale"
        $s16 = "GetHookInterface"
        $s17 = "GetConsoleWindow"
        $s18 = "GetModuleHandleA"
        $s19 = "hRA~hJAvhBAnh:Afh2A^h*AVh\"ANh"
        $s20 = "CoCreateObjectInContext"
condition:
    uint16(0) == 0x5a4d and filesize < 326KB and
    4 of them
}
    
