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
    