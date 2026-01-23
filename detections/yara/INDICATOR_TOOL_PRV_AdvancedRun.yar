import "pe"


rule DITEKSHEN_INDICATOR_TOOL_PRV_Advancedrun : FILE
{
	meta:
		description = "Detects NirSoft AdvancedRun privialge escalation tool"
		author = "ditekSHen"
		id = "c886951a-7ee9-5d38-a724-3dbba8c6ec31"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L277-L289"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "3f39e8f0629647f44a2f473d7b49a8b6adb1acd62de36420b80e7820e63854bb"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "RunAsProcessName" fullword wide
		$s2 = "Process ID/Name:" fullword wide
		$s3 = "swinsta.dll" fullword wide
		$s4 = "User of the selected process0Child of selected process (Using code injection) Specified user name and password" fullword wide
		$s5 = "\"Current User - Allow UAC Elevation$Current User - Without UAC Elevation#Administrator (Force UAC Elevation)" fullword wide

	condition:
		uint16(0)==0x5a4d and 3 of them
}
