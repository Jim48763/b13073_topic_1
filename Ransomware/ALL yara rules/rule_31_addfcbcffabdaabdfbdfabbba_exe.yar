rule addfcbcffabdaabdfbdfabbba_exe {
strings:
        $s1 = "joiSXiSXiSXiSXiSX{ej{ej{ej{ej{ej{ejwafwafwafwafwaf{ej{ej{ej{ej{ej{ejychychychychych"
        $s2 = "e\\vZOvZOvZOvZOvZOvZOxZOxZOxZOxZOxZOvVKvVKvVKvVKvVKvVK~[Q~[Q~[Q~[Q~[Q~[QzVNzVNzVNzVNzVN"
        $s3 = "oriTWiTWiTWiTWiTWvadvadvadvadvadvadydgydgydgydgydgydgp[^p[^p[^p[^p[^s^as^as^as^as^as^as^as^as^as^as^a"
        $s4 = "|gj|gj|gj|gj|gj|gj~il~il~il~il~il{fi{fi{fi{fi{fi{fixcfxcfxcfxcfxcfxcfydgydgydgydgydg"
        $s5 = "welwelwelwelwelwelaNWaNWaNWaNWaNWnVbnVbnVbnVbnVbnVbwUfwUfwUfwUfwUf~Wl~Wl~Wl~Wl~Wl~Wl"
        $s6 = "qcdqcdqcdqcdqcdM?AM?AM?AM?AM?AM?AI<>I<>I<>I<>I<>I<>VIKVIKVIKVIKVIKXKMXKMXKMXKMXKMXKM"
        $s7 = "r^jr^jr^jr^jr^jr^jjYdjYdjYdjYdjYduepuepuepuepuepuepo^go^go^go^go^go^gwgnwgnwgnwgnwgn"
        $s8 = "trrtrrtrrtrrtrrtrrd_`d_`d_`d_`d_`zxxzxxzxxzxxzxxzxxupqupqupqupqupqECCECCECCECCECCECCupqupqupqupqupq"
        $s9 = "nY\\nY\\nY\\nY\\nY\\nY\\aLOaLOaLOaLOaLOr]`r]`r]`r]`r]`r]`r]`r]`r]`r]`r]`t_bt_bt_bt_bt_bt_b"
        $s10 = "1$&1$&1$&1$&1$&1$&sfhsfhsfhsfhsfhpddpddpddpddpddpddbVVbVVbVVbVVbVVbVVmaamaamaamaamaa"
        $s11 = "wikwikwikwikwikwikwikwikwikwikwikxjlxjlxjlxjlxjleWYeWYeWYeWYeWYeWY}oq}oq}oq}oq}oq"
        $s12 = "5/05/05/05/05/0OGHOGHOGHOGHOGHOGH,$%,$%,$%,$%,$%F;=F;=F;=F;=F;=F;=H;=H;=H;=H;=H;="
        $s13 = "R=5R=5R=5R=5R=5U@8U@8U@8U@8U@8U@8U@8U@8U@8U@8U@8B-%B-%B-%B-%B-%B-%wbZwbZwbZwbZwbZ"
        $s14 = "YGFYGFYGFYGFYGF|ji|ji|ji|ji|ji|ji|ji|ji|ji|ji|jiP>=P>=P>=P>=P>=P>=wedwedwedwedwed"
        $s15 = "wjrwjrwjrwjrwjrxksxksxksxksxksxksxksxksxksxksxksqdlqdlqdlqdlqdlqdl{nv{nv{nv{nv{nv"
        $s16 = "wbewbewbewbewbemX[mX[mX[mX[mX[mX[u`cu`cu`cu`cu`cwbewbewbewbewbewbe{fi{fi{fi{fi{fi"
        $s17 = "uuymkymkymkymkymkymkrfdrfdrfdrfdrfdwkiwkiwkiwkiwkiwkivjhvjhvjhvjhvjhvjh"
        $s18 = "kpnX]nX]nX]nX]nX]nX]{ej{ej{ej{ej{ejyejyejyejyejyejyejaMRaMRaMRaMRaMRaMR{fn{fn{fn{fn{fn"
        $s19 = "jl{fi{fi{fi{fi{fi{fiePSePSePSePSePS_JM_JM_JM_JM_JM_JMePSePSFGS$"
        $s20 = "jmr]`r]`r]`r]`r]`r]`hSVhSVhSVhSVhSVhSVr]`r]`r]`r]`r]`q\\_q\\_q\\_q\\_q\\_q\\_aWZ$'"
condition:
    uint16(0) == 0x5a4d and filesize < 17043KB and
    4 of them
}
    
