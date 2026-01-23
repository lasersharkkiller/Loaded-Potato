rule High_Entropy_LNK
{
    meta:
        id = "6Dqf8gBGF21dKt03BJOXbQ"
        fingerprint = "d0b5bdad04d5894cd1136ec57bd6410180923e9267edb932c8dca6ef3a23722d"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies shortcut (LNK) file with equal or higher entropy than 6.5. Most goodware LNK files have a low entropy, lower than 6."
        category = "INFO"

    condition:
        isLNK and math.entropy(0, filesize )>=6.5
}

