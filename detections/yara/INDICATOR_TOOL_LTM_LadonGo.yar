import "pe"


rule DITEKSHEN_INDICATOR_TOOL_LTM_Ladongo : FILE
{
	meta:
		description = "Detect LadonGo tool that assists in lateral movement across a network"
		author = "ditekSHen"
		id = "4dbf7f24-b9ab-5629-8e78-667d9623dea9"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1193-L1207"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "606172b8fb251cb4ad75de40b55d74779aef6409832f6edf09068083143ec749"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$f1 = "main.VulDetection" fullword ascii
		$f2 = "main.BruteFor" fullword ascii
		$f3 = "main.RemoteExec" fullword ascii
		$f4 = "main.Exploit" fullword ascii
		$f5 = "main.Noping" fullword ascii
		$f6 = "main.LadonScan" fullword ascii
		$f7 = "main.LadonUrlScan" fullword ascii

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0x457f or uint16(0)==0xface) and 5 of ($f*)
}
