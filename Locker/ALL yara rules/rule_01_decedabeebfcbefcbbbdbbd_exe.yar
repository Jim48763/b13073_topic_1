rule decedabeebfcbefcbbbdbbd_exe {
strings:
        $s1 = "SetDefaultDllDirectories"
        $s2 = "gend Speicher."
        $s3 = "9Oxj\"J]ln6"
        $s4 = "[wnXlKBy%q`"
        $s5 = "lfI@PMq%4S<"
        $s6 = "!jY>vG-sy\""
        $s7 = "TrX'P`)# zH"
        $s8 = ".MLY!F{$ @O"
        $s9 = "Xf:el0Iq'h7"
        $s10 = "u]XGCPaAO@k"
        $s11 = "t]ES`!?GfOA"
        $s12 = "wC&#7R<o\"V"
        $s13 = "Entpacke %s"
        $s14 = "gDm)yAIUle+"
        $s15 = "fFz~9yq|x02"
        $s16 = "*n!{P|XgHW,"
        $s17 = "A0u5d#vVPEf"
        $s18 = "$ yKoI!(L71"
        $s19 = "iDsQ#1E3L\""
        $s20 = "<Q;Xz_jFiMB"
condition:
    uint16(0) == 0x5a4d and filesize < 9162KB and
    4 of them
}
    
