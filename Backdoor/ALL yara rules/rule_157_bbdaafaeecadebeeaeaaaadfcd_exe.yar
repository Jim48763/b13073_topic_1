rule bbdaafaeecadebeeaeaaaadfcd_exe {
strings:
        $s1 = "reldnaHemarFxxC__"
        $s2 = "__CxxFrameHandler"
        $s3 = "xedaerhtnigeb_"
        $s4 = "tablit l'action pr"
        $s5 = "sutatSecivreSyreuQ"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "FileDescription"
        $s9 = "elbisiVwodniWsI"
        $s10 = "SetThreadPriority"
        $s11 = "Ouvre ce document"
        $s12 = ")Restaure la fen"
        $s13 = "AeldnaHeludoMteG"
        $s14 = "GetModuleHandleA"
        $s15 = "dnammoc\\nepo\\llehs\\s%"
        $s16 = "dIdaerhTtnerruCteG"
        $s17 = "emaNyldneirF"
        $s18 = "EnableWindow"
        $s19 = "emiTlacoLteG"
        $s20 = "tnuoCkciTteG"
condition:
    uint16(0) == 0x5a4d and filesize < 105KB and
    4 of them
}
    
