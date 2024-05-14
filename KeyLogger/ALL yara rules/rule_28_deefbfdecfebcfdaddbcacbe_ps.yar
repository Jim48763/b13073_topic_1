rule deefbfdecfebcfdaddbcacbe_ps {
strings:
        $s1 = "echo 'Running on %%x'"
        $s2 = "GOTO processargs"
        $s3 = "if !ERRORLEVEL! == 0 ("
        $s4 = "IF \"%FLAG%\"==\"-\" ("
        $s5 = "SET ARG=%1"
        $s6 = "IF DEFINED ARG ("
        $s7 = "EXIT /B 1"
        $s8 = "@echo off"
        $s9 = "GOTO :EOF"
        $s10 = ":android"
        $s11 = ":windows"
        $s12 = ") else ("
        $s13 = ":linux"
        $s14 = "SHIFT"
condition:
    uint16(0) == 0x5a4d and filesize < 8KB and
    4 of them
}
    
