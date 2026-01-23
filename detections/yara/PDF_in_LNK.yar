rule PDF_in_LNK
{
    meta:
        id = "7U50CQK54jXHGYojYg4wKe"
        fingerprint = "5640fd2e7a31adf7f080658f07084d5e7b9dd89d2e58c49ffd7fe50f16bfcaa2"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Adobe Acrobat artefacts in shortcut (LNK) files. A PDF document is typically used as decoy in a malicious LNK."
        category = "INFO"

    strings:
        $ = ".pdf" ascii wide nocase
        $ = "%PDF" ascii wide nocase

    condition:
        isLNK and any of them
}

