rule MSOffice_in_LNK
{
    meta:
        id = "5wsZnuCXdcxZ1DbLHFC4pX"
        fingerprint = "ac2e453ed19a4f30f17a1c7ff4c8dfcd00b2c2fc53c7ab05d32f5e6a91326da1"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2025-02-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Microsoft Office artefacts in shortcut (LNK) files."
        category = "INFO"

    strings:
        $ = ".docm" ascii wide nocase
        $ = ".dotm" ascii wide nocase
        $ = ".potm" ascii wide nocase
        $ = ".ppsm" ascii wide nocase
        $ = ".pptm" ascii wide nocase
        $ = ".rtf" ascii wide nocase
        $ = ".sldm" ascii wide nocase
        $ = ".slk" ascii wide nocase
        $ = ".wll" ascii wide nocase
        $ = ".xla" ascii wide nocase
        $ = ".xlam" ascii wide nocase
        $ = ".xls" ascii wide nocase
        $ = ".xlsm" ascii wide nocase
        $ = ".xll" ascii wide nocase
        $ = ".xltm" ascii wide nocase

    condition:
        isLNK and any of them
}

