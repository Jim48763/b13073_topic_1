rule fedceecaceaeebfafafbbbcfefdb_exe {
strings:
        $s1 = "Tip of the Day"
        $s2 = "M3efA=z,L6c"
        $s3 = "ProductName"
        $s4 = "2KoHQpbvw;V"
        $s5 = ",M)<hwjWH/*"
        $s6 = "VarFileInfo"
        $s7 = "/3D;qs{B~kQ"
        $s8 = "FileDescription"
        $s9 = "CD;0;EFE;GHIIIF\\EEj;?."
        $s10 = "Lu[\\;EE\\IPQRSTUUUU;"
        $s11 = "kbyCe[8K\\f/"
        $s12 = "~~a#N]-m(vWr"
        $s13 = "Smo[cYm9sAQJ"
        $s14 = "22\"*D>`9pw]"
        $s15 = "5Fm([\\8@]b%"
        $s16 = "<XJ<gcaFpWs1"
        $s17 = "l!]L\\}%4B8e"
        $s18 = "=\\,L)KhwjWhB"
        $s19 = "{AI8z[A.nnfNp"
        $s20 = "TPW+XZ:.XhNN}"
condition:
    uint16(0) == 0x5a4d and filesize < 196KB and
    4 of them
}
    
