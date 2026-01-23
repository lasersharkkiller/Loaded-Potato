import "pe"


rule DITEKSHEN_INDICATOR_TOOL_Dwagentsvc : FILE
{
	meta:
		description = "Detect DWAgent Remote Administration Tool service"
		author = "ditekSHen"
		id = "5d124c20-a0f8-5e82-8bab-93a782a2a649"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1541-L1553"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "590d41d2e433a7a1bb373fbd0b0d47818a9867bee0399101881b05e83b586f6e"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "\\native\\dwagupd.dll" wide
		$s2 = "\\native\\dwagsvc.exe\" run" wide
		$s3 = "CreateServiceW" fullword ascii
		$s4 = /dwagent\.(pid|start|stop)/ wide
		$s5 = "Check updating..." wide

	condition:
		uint16(0)==0x5a4d and 4 of them
}
