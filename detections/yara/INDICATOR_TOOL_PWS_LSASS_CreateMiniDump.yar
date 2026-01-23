import "pe"


rule DITEKSHEN_INDICATOR_TOOL_PWS_LSASS_Createminidump : FILE
{
	meta:
		description = "Detects CreateMiniDump tool"
		author = "ditekSHen"
		id = "0d8642d1-2ed9-5270-a54a-6ba788026f5f"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L712-L724"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "577ccc783554363c0bed80d9642e8a0f107fc2ec66d84f76b9556aa3506c86c0"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "lsass.dmp" fullword wide
		$s2 = "lsass dumped successfully!" ascii
		$s3 = "Got lsass.exe PID:" ascii
		$s4 = "\\experiments\\CreateMiniDump\\CreateMiniDump\\" ascii
		$s5 = "MiniDumpWriteDump" fullword ascii

	condition:
		uint16(0)==0x5a4d and 2 of them
}
