rule aadddcbaeeecbbbdbdfbad_exe {
strings:
        $s1 = "]jWzwzHvHv[~[~laL"
        $s2 = "ResolveTypeHandle"
        $s3 = "FileSystemAccessRule"
        $s4 = "FlagsAttribute"
        $s5 = "EnterDebugMode"
        $s6 = "FileSystemSecurity"
        $s7 = "STAThreadAttribute"
        $s8 = "qUZg\"9m7iv"
        $s9 = "crazysound7"
        $s10 = "wJ{k`YxATC:"
        $s11 = "kr9jZvD4p$G"
        $s12 = "% 7~K{[k#h/"
        $s13 = "SoundPlayer"
        $s14 = "m`_a[yAqQ~p"
        $s15 = "e*w:rV]vj^F"
        $s16 = "dp.Qq\"4=Y&"
        $s17 = "3[h'W$%|Q=*"
        $s18 = "\"f!KxqitbQ"
        $s19 = "UX_T*fil:zc"
        $s20 = "Ud}m7<o^5T]"
condition:
    uint16(0) == 0x5a4d and filesize < 8287KB and
    4 of them
}
    
