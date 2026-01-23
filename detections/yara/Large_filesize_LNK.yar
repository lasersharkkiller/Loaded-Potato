rule Large_filesize_LNK
{
    meta:
        id = "2N6jerukOyU2qFFtcMtnWt"
        fingerprint = "a8168e65294bfc0b9ffca544891b818b37feb5b780ab357efbb56638c6578242"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies shortcut (LNK) file larger than 100KB. Most goodware LNK files are smaller than 100KB."
        category = "INFO"

    condition:
        isLNK and filesize >100KB
}

