rule beafaabfbddbfddcdfdabda_exe {
strings:
        $s1 = "}Q\"ABV0@Ym"
        $s2 = ",W4C7P8T:O>"
        $s3 = "1<&B-_0F\"@"
        $s4 = "De821VirtuN"
        $s5 = "&yh8lQ4Hx<0"
        $s6 = "V DNASRLUk\\"
        $s7 = "l7l8i9c:aY%}"
        $s8 = "OLEAUT32.dll"
        $s9 = "AuthenticAMD?"
        $s10 = "2345NNN*6789NNNN:;<="
        $s11 = "VirtualProtect"
        $s12 = "lrKMoBNc{R"
        $s13 = "XR(Di1!+WP"
        $s14 = "*{]|N&}e~q"
        $s15 = " 0*a+,d&-o"
        $s16 = "s#v6f,h5Pb"
        $s17 = "4.`!|9@r\""
        $s18 = "rom th&GNU"
        $s19 = "LVhp%PW\"M"
        $s20 = "Oe<47USt!J"
condition:
    uint16(0) == 0x5a4d and filesize < 1094KB and
    4 of them
}
    
