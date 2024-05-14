rule dedaefedfcfcddbcabceb_exe {
strings:
        $s1 = "03SWIx]!=F;"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = ".)j$>'fw5Pm"
        $s5 = "FileDescription"
        $s6 = "Entrust.net1@0>"
        $s7 = "lRankiqnesHs.exe"
        $s8 = "GetModuleHandleA"
        $s9 = ">z%{:RH44pW5"
        $s10 = "    </trustInfo>"
        $s11 = "        version=\"1.0.0.0\""
        $s12 = "r,E%*iX?\""
        $s13 = "79K%q&O-v="
        $s14 = "hezrH~kQyv"
        $s15 = "+h:*!cWKY>"
        $s16 = "/mJjMT63<g"
        $s17 = "<;o^pFq_*E"
        $s18 = "7-P(6eEz`h"
        $s19 = ".FRKS%Dnd2"
        $s20 = "2cRICWq\"y"
condition:
    uint16(0) == 0x5a4d and filesize < 804KB and
    4 of them
}
    
