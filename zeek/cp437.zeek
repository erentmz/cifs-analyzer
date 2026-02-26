module CP437;

export {
    global cp437_to_utf8: function(s: string): string;
    global strip_nb_suffix_and_pad: function(s: string): string;
    global sanitize_nb_name: function(name_utf8: string): string;
}

# CP437 (single-byte) -> UTF-8 eşleme tablosu, anahtar tek baytlık string "\x00" .. "\xff"
const CP437_UTF8: table[string] of string = {
    ["\x00"] = "\x00", ["\x01"] = "\x01", ["\x02"] = "\x02", ["\x03"] = "\x03",
    ["\x04"] = "\x04", ["\x05"] = "\x05", ["\x06"] = "\x06", ["\x07"] = "\x07",
    ["\x08"] = "\x08", ["\x09"] = "\x09", ["\x0a"] = "\x0a", ["\x0b"] = "\x0b",
    ["\x0c"] = "\x0c", ["\x0d"] = "\x0d", ["\x0e"] = "\x0e", ["\x0f"] = "\x0f",
    ["\x10"] = "\x10", ["\x11"] = "\x11", ["\x12"] = "\x12", ["\x13"] = "\x13",
    ["\x14"] = "\x14", ["\x15"] = "\x15", ["\x16"] = "\x16", ["\x17"] = "\x17",
    ["\x18"] = "\x18", ["\x19"] = "\x19", ["\x1a"] = "\x1a", ["\x1b"] = "\x1b",
    ["\x1c"] = "\x1c", ["\x1d"] = "\x1d", ["\x1e"] = "\x1e", ["\x1f"] = "\x1f",
    ["\x20"] = "\x20", ["\x21"] = "\x21", ["\x22"] = "\x22", ["\x23"] = "\x23",
    ["\x24"] = "\x24", ["\x25"] = "\x25", ["\x26"] = "\x26", ["\x27"] = "\x27",
    ["\x28"] = "\x28", ["\x29"] = "\x29", ["\x2a"] = "\x2a", ["\x2b"] = "\x2b",
    ["\x2c"] = "\x2c", ["\x2d"] = "\x2d", ["\x2e"] = "\x2e", ["\x2f"] = "\x2f",
    ["\x30"] = "\x30", ["\x31"] = "\x31", ["\x32"] = "\x32", ["\x33"] = "\x33",
    ["\x34"] = "\x34", ["\x35"] = "\x35", ["\x36"] = "\x36", ["\x37"] = "\x37",
    ["\x38"] = "\x38", ["\x39"] = "\x39", ["\x3a"] = "\x3a", ["\x3b"] = "\x3b",
    ["\x3c"] = "\x3c", ["\x3d"] = "\x3d", ["\x3e"] = "\x3e", ["\x3f"] = "\x3f",
    ["\x40"] = "\x40", ["\x41"] = "\x41", ["\x42"] = "\x42", ["\x43"] = "\x43",
    ["\x44"] = "\x44", ["\x45"] = "\x45", ["\x46"] = "\x46", ["\x47"] = "\x47",
    ["\x48"] = "\x48", ["\x49"] = "\x49", ["\x4a"] = "\x4a", ["\x4b"] = "\x4b",
    ["\x4c"] = "\x4c", ["\x4d"] = "\x4d", ["\x4e"] = "\x4e", ["\x4f"] = "\x4f",
    ["\x50"] = "\x50", ["\x51"] = "\x51", ["\x52"] = "\x52", ["\x53"] = "\x53",
    ["\x54"] = "\x54", ["\x55"] = "\x55", ["\x56"] = "\x56", ["\x57"] = "\x57",
    ["\x58"] = "\x58", ["\x59"] = "\x59", ["\x5a"] = "\x5a", ["\x5b"] = "\x5b",
    ["\x5c"] = "\x5c", ["\x5d"] = "\x5d", ["\x5e"] = "\x5e", ["\x5f"] = "\x5f",
    ["\x60"] = "\x60", ["\x61"] = "\x61", ["\x62"] = "\x62", ["\x63"] = "\x63",
    ["\x64"] = "\x64", ["\x65"] = "\x65", ["\x66"] = "\x66", ["\x67"] = "\x67",
    ["\x68"] = "\x68", ["\x69"] = "\x69", ["\x6a"] = "\x6a", ["\x6b"] = "\x6b",
    ["\x6c"] = "\x6c", ["\x6d"] = "\x6d", ["\x6e"] = "\x6e", ["\x6f"] = "\x6f",
    ["\x70"] = "\x70", ["\x71"] = "\x71", ["\x72"] = "\x72", ["\x73"] = "\x73",
    ["\x74"] = "\x74", ["\x75"] = "\x75", ["\x76"] = "\x76", ["\x77"] = "\x77",
    ["\x78"] = "\x78", ["\x79"] = "\x79", ["\x7a"] = "\x7a", ["\x7b"] = "\x7b",
    ["\x7c"] = "\x7c", ["\x7d"] = "\x7d", ["\x7e"] = "\x7e", ["\x7f"] = "\x7f",
    ["\x80"] = "\xc2\x80", ["\x81"] = "\xc3\xbc", ["\x82"] = "\xc3\xa9", ["\x83"] = "\xc3\xa2",
    ["\x84"] = "\xc3\xa4", ["\x85"] = "\xc3\xa0", ["\x86"] = "\xc3\xa5", ["\x87"] = "\xc3\xa7",
    ["\x88"] = "\xc3\xaa", ["\x89"] = "\xc3\xab", ["\x8a"] = "\xc3\xa8", ["\x8b"] = "\xc3\xaf",
    ["\x8c"] = "\xc3\xae", ["\x8d"] = "\xc3\xac", ["\x8e"] = "\xc3\x84", ["\x8f"] = "\xc3\x85",
    ["\x90"] = "\xc3\x89", ["\x91"] = "\xc3\xa6", ["\x92"] = "\xc3\x86", ["\x93"] = "\xc3\xb4",
    ["\x94"] = "\xc3\xb6", ["\x95"] = "\xc3\xb2", ["\x96"] = "\xc3\xbb", ["\x97"] = "\xc3\xb9",
    ["\x98"] = "\xc3\xbf", ["\x99"] = "\xc3\x96", ["\x9a"] = "\xc3\x9c", ["\x9b"] = "\xc2\xa2",
    ["\x9c"] = "\xc2\xa3", ["\x9d"] = "\xc2\xa5", ["\x9e"] = "\xe2\x82\xa7", ["\x9f"] = "\xc6\x92",
    ["\xa0"] = "\xc3\xa1", ["\xa1"] = "\xc3\xad", ["\xa2"] = "\xc3\xb3", ["\xa3"] = "\xc3\xba",
    ["\xa4"] = "\xc3\xb1", ["\xa5"] = "\xc3\x91", ["\xa6"] = "\xc2\xaa", ["\xa7"] = "\xc2\xba",
    ["\xa8"] = "\xc2\xbf", ["\xa9"] = "\xe2\x8c\x90", ["\xaa"] = "\xc2\xac", ["\xab"] = "\xc2\xbd",
    ["\xac"] = "\xc2\xbc", ["\xad"] = "\xc2\xa1", ["\xae"] = "\xc2\xab", ["\xaf"] = "\xc2\xbb",
    ["\xb0"] = "\xe2\x96\x91", ["\xb1"] = "\xe2\x96\x92", ["\xb2"] = "\xe2\x96\x93", ["\xb3"] = "\xe2\x94\x82",
    ["\xb4"] = "\xe2\x9c\x82", ["\xb5"] = "\xe2\x94\xa4", ["\xb6"] = "\xe2\x95\xa1", ["\xb7"] = "\xe2\x95\xa2",
    ["\xb8"] = "\xe2\x95\x96", ["\xb9"] = "\xe2\x95\x95", ["\xba"] = "\xe2\x95\xa3", ["\xbb"] = "\xe2\x95\x91",
    ["\xbc"] = "\xe2\x95\x97", ["\xbd"] = "\xe2\x95\x9d", ["\xbe"] = "\xe2\x95\x9c", ["\xbf"] = "\xe2\x95\x9b",
    ["\xc0"] = "\xe2\x94\x90", ["\xc1"] = "\xe2\x94\x94", ["\xc2"] = "\xe2\x94\xb4", ["\xc3"] = "\xe2\x94\xac",
    ["\xc4"] = "\xe2\x94\x9c", ["\xc5"] = "\xe2\x94\x80", ["\xc6"] = "\xe2\x94\xbc", ["\xc7"] = "\xe2\x95\x9e",
    ["\xc8"] = "\xe2\x95\x9f", ["\xc9"] = "\xe2\x95\x9a", ["\xca"] = "\xe2\x95\x94", ["\xcb"] = "\xe2\x95\xa9",
    ["\xcc"] = "\xe2\x95\xa6", ["\xcd"] = "\xe2\x95\xa0", ["\xce"] = "\xe2\x95\x90", ["\xcf"] = "\xe2\x95\xac",
    ["\xd0"] = "\xe2\x95\xa7", ["\xd1"] = "\xe2\x95\xa8", ["\xd2"] = "\xe2\x95\xa4", ["\xd3"] = "\xe2\x95\xa5",
    ["\xd4"] = "\xe2\x95\x99", ["\xd5"] = "\xe2\x95\x98", ["\xd6"] = "\xe2\x95\x92", ["\xd7"] = "\xe2\x95\x93",
    ["\xd8"] = "\xe2\x95\xab", ["\xd9"] = "\xe2\x95\xaa", ["\xda"] = "\xe2\x94\x98", ["\xdb"] = "\xe2\x96\x88",
    ["\xdc"] = "\xe2\x96\x84", ["\xdd"] = "\xe2\x96\x8c", ["\xde"] = "\xe2\x96\x90", ["\xdf"] = "\xe2\x96\x80",
    ["\xe0"] = "\xce\xb1", ["\xe1"] = "\xc3\x9f", ["\xe2"] = "\xce\x93", ["\xe3"] = "\xcf\x80",
    ["\xe4"] = "\xce\xa3", ["\xe5"] = "\xcf\x83", ["\xe6"] = "\xce\xbc", ["\xe7"] = "\xcf\x84",
    ["\xe8"] = "\xce\xa6", ["\xe9"] = "\xce\x98", ["\xea"] = "\xce\xa9", ["\xeb"] = "\xce\xb4",
    ["\xec"] = "\xe2\x88\x9e", ["\xed"] = "\xcf\x86", ["\xee"] = "\xce\xb5", ["\xef"] = "\xe2\x88\xa9",
    ["\xf0"] = "\xe2\x89\xa1", ["\xf1"] = "\xc2\xb1", ["\xf2"] = "\xe2\x89\xa5", ["\xf3"] = "\xe2\x89\xa4",
    ["\xf4"] = "\xe2\x8c\xa0", ["\xf5"] = "\xe2\x8c\xa1", ["\xf6"] = "\xc3\xb7", ["\xf7"] = "\xe2\x89\x88",
    ["\xf8"] = "\xc2\xb0", ["\xf9"] = "\xe2\x88\x99", ["\xfa"] = "\xc2\xb7", ["\xfb"] = "\xe2\x88\x9a",
    ["\xfc"] = "\xe2\x81\xbf", ["\xfd"] = "\xc2\xb2", ["\xfe"] = "\xe2\x96\xa0", ["\xff"] = "\xc2\xa0",
};

# CP437 kodlamalı bir stringi UTF-8 stringe dönüştürür.
# CP437_UTF8 tablosunu kullanarak her baytı karşılığına map eder.
# Eğer tabloda olmayan bir bayt gelirse yerine U+FFFD (replacement char) koyar.
function cp437_to_utf8(s: string): string
    {
    local out = "";
    for ( c in s )
        {
        if ( c in CP437_UTF8 )
            out += CP437_UTF8[c];
        else
            out += "\xef\xbf\xbd";  # U+FFFD
        }
    return out;
    }

# NetBIOS adlarındaki gereksiz ekleri ve boşlukları temizler.
# 1) Sondaki padding boşluklarını (0x20) kırpar.
# 2) Eğer son karakter < 0x20 ise (örn. 0x00, 0x1B gibi suffix kodları) onu atar.
# 3) Suffix atıldıktan sonra tekrar sondaki boşlukları kırpar.
function strip_nb_suffix_and_pad(s: string): string
    {
    local n = s;

    # trailing space (0x20) kırp
    while ( |n| > 0 && n[|n|-1:|n|] == " " )
        n = n[0:|n|-1];

    # sonda NetBIOS suffix (< 0x20) varsa at
    if ( |n| > 0 && n[|n|-1:|n|] < "\x20" )
        n = n[0:|n|-1];

    # tekrar trailing space kırp
    while ( |n| > 0 && n[|n|-1:|n|] == " " )
        n = n[0:|n|-1];

    return n;
    }

# UTF-8 stringlerin sonundaki boşlukları temizler.
# strip_nb_suffix_and_pad sonrası ekstra güvenlik olarak kullanılır.
# Örn: "WORKGROUP   " -> "WORKGROUP"
function sanitize_nb_name(name_utf8: string): string
    {
    local n = name_utf8;
    while ( |n| > 0 && n[|n|-1:|n|] == " " )
        n = n[0:|n|-1];
    return n;
    }





