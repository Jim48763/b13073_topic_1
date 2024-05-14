rule fbcaffbafadbedceaaecceba_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "Per Primitiva Vice Os"
        $s3 = "CreateIoCompletionPort"
        $s4 = "<dependency><dependentAssembly>"
        $s5 = ";!@EnstallEnd@!Rar!"
        $s6 = "112 North Curry Street1"
        $s7 = "utj\"j Pj:h0GA"
        $s8 = "gvceXcfUhq.com"
        $s9 = "_beginthreadex"
        $s10 = "Montrovorto Tia Ci Kabo"
        $s11 = "PD1/wL&pb\""
        $s12 = "F+P1oQ*5;$K"
        $s13 = "Vg!onr%cP(:"
        $s14 = "BeginPrompt"
        $s15 = "'x nL5;CT8_"
        $s16 = ":vBy=M|c3tI"
        $s17 = "{Lxvg0d~X*."
        $s18 = "VarFileInfo"
        $s19 = ".M}O]?!3I%d"
        $s20 = "MyDocuments"
condition:
    uint16(0) == 0x5a4d and filesize < 1819KB and
    4 of them
}
    
