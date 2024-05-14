rule fccceacdfdedefeebdabfdccacefff_cmd {
strings:

condition:
    uint16(0) == 0x5a4d and filesize < 6KB and
    all of them
}
    