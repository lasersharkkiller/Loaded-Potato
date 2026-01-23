rule Long_RelativePath_LNK
{
    meta:
        id = "2ogEIXl8u2qUbIgxTmruYX"
        fingerprint = "4b822248bade98d0528ab13549797c225784d7f953fe9c14d178c9d530fb3e55"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2025-02-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies shortcut (LNK) file with a long relative path. Might be used in an attempt to hide the path."
        category = "INFO"

    strings:
        $ = "..\\..\\..\\..\\..\\..\\" ascii wide nocase

    condition:
        isLNK and any of them
}

