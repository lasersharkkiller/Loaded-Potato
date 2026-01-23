import "pe"


rule DITEKSHEN_INDICATOR_TOOL_PWS_Fgdump : FILE
{
	meta:
		description = "detects all versions of the password dumping tool, fgdump. Observed to be used by DustSquad group."
		author = "ditekSHen"
		id = "2759fce2-db2a-5a48-bb37-931fd847a32d"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L64-L81"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "fdccd91a84374f7c94843bd9c2191720959416acf2e33d7b28b42d63d7ea4ce3"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "dumping server %s" ascii
		$s2 = "dump on server %s" ascii
		$s3 = "dump passwords: %s" ascii
		$s4 = "Dumping cache" nocase ascii
		$s5 = "SECURITY\\Cache" ascii
		$s6 = "LSASS.EXE process" ascii
		$s7 = " AntiVirus " nocase ascii
		$s8 = " IPC$ " ascii
		$s9 = "Exec failed, GetLastError returned %d" fullword ascii
		$10 = "writable connection to %s" ascii

	condition:
		uint16(0)==0x5a4d and 5 of them
}
