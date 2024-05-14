import pe
rule abdbeddcdcacbcacbaecbbefbda_exe {
strings:
        $s1 = "Py_SetProgramName"
        $s2 = "s$728242<2:262>2129\"NT"
        $s3 = "Directory not empty"
        $s4 = "SetConsoleCtrlHandler"
        $s5 = "requests.__version__)"
        $s6 = "GetConsoleOutputCP"
        $s7 = "No child processes"
        $s8 = "operation canceled"
        $s9 = "Tcl_GetVar2"
        $s10 = "F#bgn?MwN|%"
        $s11 = "2ao?(xvDt7g"
        $s12 = "x_OJz\"P}7+"
        $s13 = "OIqUz)g`{wj"
        $s14 = "qYS~5u<ps0A"
        $s15 = "E1qI0JM.z&#"
        $s16 = "L?;lfIU}y#e"
        $s17 = "eM>4,2O}(#n"
        $s18 = "'0%Uk7z&^!1"
        $s19 = "lEcMF6KQN4W"
        $s20 = "* ny()LIP$@"
condition:
    uint16(0) == 0x5a4d and filesize < 16892KB and
    4 of them
}
    
rule badececbdeeafcddebec_exe {
strings:
        $s1 = "Py_SetProgramName"
        $s2 = "s$728242<2:262>2129\"NT"
        $s3 = "Directory not empty"
        $s4 = "SetConsoleCtrlHandler"
        $s5 = "requests.__version__)"
        $s6 = "No child processes"
        $s7 = "F#bgn?MwN|%"
        $s8 = "!,'=/\"k%{j"
        $s9 = "5?69gM_{mb|"
        $s10 = "9Kk.g!/|_ry"
        $s11 = "2ao?(xvDt7g"
        $s12 = "qYS~5u<ps0A"
        $s13 = "eM>4,2O}(#n"
        $s14 = "lEcMF6KQN4W"
        $s15 = "3K0Y?D7!Qu "
        $s16 = "s\"r5UF:qT`"
        $s17 = "*O:+cBA[$? "
        $s18 = "3z0M~jH])_="
        $s19 = "<'^wVf{rk}C"
        $s20 = "Zv/Hj.nlu\""
condition:
    uint16(0) == 0x5a4d and filesize < 12956KB and
    4 of them
}
    
rule fbdffebfbabacfdfeebecced_exe {
strings:
        $s1 = "              set through the setsampwidth() or setparams() method"
        $s2 = "        this function one or more times, before using"
        $s3 = "        Clear the cache for all loggers in loggerDict"
        $s4 = "        the second is not the last triple in the list, then i+n != i' or"
        $s5 = "   is used in the interactive interpreter to store the result of the"
        $s6 = "uVoidPointer_cffi.__init__"
        $s7 = "      0 - user site directory is enabled"
        $s8 = "    Returns an Element instance."
        $s9 = "z!_SafeQueue._on_queue_feeder_error)"
        $s10 = "          <marker ID> (2 bytes, must be > 0)"
        $s11 = "sqlite3_str_value"
        $s12 = "ApplyResult._set)"
        $s13 = "uCfbMode.__init__"
        $s14 = "_parse_optionalr$"
        $s15 = "doModuleCleanups`"
        $s16 = "mon_decimal_point"
        $s17 = "uIncorrect length"
        $s18 = "-yscrollincrement"
        $s19 = "WeakSet.__isub__c"
        $s20 = "PyType_GenericNew"
condition:
    uint16(0) == 0x5a4d and filesize < 26394KB and
    4 of them
}
    
rule cfbfbfffacacdeeecdae_exe {
strings:
        $s1 = "Py_SetProgramName"
        $s2 = "?< <0<(<8<$<4<,<<<\"<2<*<:<&<6<.<><!<1<)<9<%<5<-<=<#<3<+<;<'<7</<?"
        $s3 = "C@()4$444,4<4\"424*4:4&494%454-4=4#434+4;4'474/4?"
        $s4 = "Directory not empty"
        $s5 = "SetConsoleCtrlHandler"
        $s6 = "GetConsoleOutputCP"
        $s7 = "No child processes"
        $s8 = "operation canceled"
        $s9 = "Tcl_GetVar2"
        $s10 = "UanB7*ZyY-?"
        $s11 = "9Kk.g!/|_ry"
        $s12 = "kwN.lfp/4Td"
        $s13 = "Zf\"zpyhF D"
        $s14 = "^bINcSXUaj;"
        $s15 = "oKyi]EuI%=7"
        $s16 = "s5O>{r\"<iQ"
        $s17 = "9m-N6\"C5:A"
        $s18 = "}D\"sK.h 40"
        $s19 = "BLVJ mEdU^T"
        $s20 = "BC=FNbyTsdH"
condition:
    uint16(0) == 0x5a4d and filesize < 12216KB and
    4 of them
}
    
rule efdfaaafabcfffadbcdffd_exe {
strings:
        $s1 = "Py_SetProgramName"
        $s2 = "?q q0q(q8q$q4q,q<q\"q2q*q:q&q6q.q>q!q1q)q9q%q5q-Q"
        $s3 = "?r r0r(r8r$r4r,r<r\"r2r*r:r&r6r.r>r!r1r)r9r%r5r-R"
        $s4 = "?p p0p(p8p$p4p,p<p\"p2p*p:p&p6p.p>p!p1p)p9p%p5p-P"
        $s5 = "pubsub.core.callables)"
        $s6 = "WzAzq^nAajr~Zq~narazZP"
        $s7 = "Directory not empty"
        $s8 = "SetConsoleCtrlHandler"
        $s9 = "No child processes"
        $s10 = "bMain.exe.manifest"
        $s11 = "*NSyfP%`o?E"
        $s12 = "&nj+4z^,x9P"
        $s13 = "x_OJz\"P}7+"
        $s14 = "=|AzX,H{q)I"
        $s15 = "QGg@TJLR*K+"
        $s16 = "Vq]JWYr*kh#"
        $s17 = "BED1\"LX`Mh"
        $s18 = "`7w#]uc Q:?"
        $s19 = "eE<]^Z&UtK{"
        $s20 = "#%PzfNKHw0>"
condition:
    uint16(0) == 0x5a4d and filesize < 11478KB and
    4 of them
}
    