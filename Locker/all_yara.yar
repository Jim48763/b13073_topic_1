import pe
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
    
rule dfffdbaeffceefefaaab_exe {
strings:
        $s1 = "set_TransparencyKey"
        $s2 = "RuntimeHelpers"
        $s3 = "STAThreadAttribute"
        $s4 = "AuthenticationMode"
        $s5 = "ProductName"
        $s6 = "VarFileInfo"
        $s7 = "MsgBoxStyle"
        $s8 = "My.Computer"
        $s9 = "_CorExeMain"
        $s10 = "ThreadStaticAttribute"
        $s11 = "set_MinimizeBox"
        $s12 = "get_WebBrowser1"
        $s13 = "FileDescription"
        $s14 = "set_PasswordChar"
        $s15 = "AutoSaveSettings"
        $s16 = "InitializeComponent"
        $s17 = "GraphicsUnit"
        $s18 = "set_TabIndex"
        $s19 = "Synchronized"
        $s20 = "set_ReadOnly"
condition:
    uint16(0) == 0x5a4d and filesize < 26KB and
    4 of them
}
    
rule dcadecedecaaabdfccfd_exe {
strings:
        $s1 = "EVariantBadVarTypeError"
        $s2 = "'%s' is not a valid date"
        $s3 = "SetWindowTheme"
        $s4 = "RegSetValueExA"
        $s5 = "OnMouseWheelUp"
        $s6 = "TWinControlActionLink"
        $s7 = "TContextPopupEvent"
        $s8 = "TPrintScale"
        $s9 = "Medium Gray"
        $s10 = "TDragObject"
        $s11 = "TBrushStyle"
        $s12 = "GroupIndex$"
        $s13 = "fsStayOnTop"
        $s14 = "LoadStringA"
        $s15 = "OnDrawItem("
        $s16 = "clBtnShadow"
        $s17 = "Window Text"
        $s18 = "GetWindowDC"
        $s19 = "TMenuMeasureItemEvent"
        $s20 = "GetKeyboardType"
condition:
    uint16(0) == 0x5a4d and filesize < 481KB and
    4 of them
}
    
rule dfcdcacedbfcbcdddfacaecf_exe {
strings:
        $s1 = "SetDefaultDllDirectories"
        $s2 = ">$>,>4><>D>L>T>\\>d>l>t>|> ?$?4?8?@?X?h?l?|?"
        $s3 = "pH=NUt.K>}q"
        $s4 = "P\"?swM*96~"
        $s5 = "%.#(0),2D3C"
        $s6 = "q CR#^4wbre"
        $s7 = "\"YMsGw7^[l"
        $s8 = "aV:s\"W Y}J"
        $s9 = "QNe8@d`qi_;"
        $s10 = "{&Uqc=`iy(6"
        $s11 = "`A0^SnP3+X)"
        $s12 = "xLPr=J>U+9@"
        $s13 = "LZ3S-\"INq&"
        $s14 = "Xd/We+$rhR'"
        $s15 = "T2a+#5j@\"Y"
        $s16 = "}imchCFstxl"
        $s17 = "wMuKs8,nY<+"
        $s18 = "$P &N40F+)c"
        $s19 = "}De^&dT8l7U"
        $s20 = "c!tp2#Nw*H?"
condition:
    uint16(0) == 0x5a4d and filesize < 5269KB and
    4 of them
}
    