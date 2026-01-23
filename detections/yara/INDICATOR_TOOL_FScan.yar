import "pe"


rule DITEKSHEN_INDICATOR_TOOL_Fscan : FILE
{
	meta:
		description = "Detects GoGo scan tool"
		author = "ditekSHen"
		id = "3bf73853-15c1-54f7-866a-6a7632e39f19"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1652-L1666"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "b107eb767454c4c084a7237c107c8414bdb03c324902769ac544c5903e346e17"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "fscan version:" ascii
		$s2 = "Citrix-ConfProxyCitrix-MetaframeCitrix-NetScalerCitrix-XenServerCitrix_Netscaler" ascii
		$s3 = "(AkamaiGHost)(DESCRIPTION=(Typecho</a>)(^.+)([0-9]+)(confluence.)(dotDefender)" ascii
		$s4 = "/fscan/" ascii
		$s5 = "WebScan.CheckDatas" ascii
		$s6 = "'Exploit.Test" ascii
		$s7 = "rules:" ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}
