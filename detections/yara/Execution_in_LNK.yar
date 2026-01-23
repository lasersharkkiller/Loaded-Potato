rule Execution_in_LNK
{
    meta:
        id = "77XnooZUMUCCdEuppmQ0My"
        fingerprint = "cf4910d057f099ef2d2b6fc80739a41e3594c500e6b4eca0fc8f64e48f6dcefb"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies execution artefacts in shortcut (LNK) files."
        category = "INFO"

    strings:
        $ = "cmd.exe" ascii wide nocase
        $ = "/c echo" ascii wide nocase
        $ = "/c start" ascii wide nocase
        $ = "/c set" ascii wide nocase
        $ = "%COMSPEC%" ascii wide nocase
        $ = "rundll32.exe" ascii wide nocase
        $ = "regsvr32.exe" ascii wide nocase
        $ = "Assembly.Load" ascii wide nocase
        $ = "[Reflection.Assembly]::Load" ascii wide nocase
        $ = "process call" ascii wide nocase

    condition:
        isLNK and any of them
}

