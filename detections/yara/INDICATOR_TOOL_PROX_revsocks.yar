import "pe"


rule DITEKSHEN_INDICATOR_TOOL_PROX_Revsocks : FILE
{
	meta:
		description = "Detects revsocks Reverse socks5 tunneler with SSL/TLS and proxy support"
		author = "ditekSHen"
		id = "f85bc557-40ab-5533-8a89-a2de9bbc9ad9"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1307-L1321"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "4a8e68f25b7ba10b0eb9772ed4ba2b9c6566768f2b5a2859df8bac644d196bf3"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "main.agentpassword" fullword ascii
		$s2 = "main.connectForSocks" fullword ascii
		$s3 = "main.connectviaproxy" fullword ascii
		$s4 = "main.DnsConnectSocks" fullword ascii
		$s5 = "main.listenForAgents" fullword ascii
		$s6 = "main.listenForClients" fullword ascii
		$s7 = "main.getPEMs" fullword ascii

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0x457f) and 4 of them
}
