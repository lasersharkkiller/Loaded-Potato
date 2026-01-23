import "pe"


rule DITEKSHEN_INDICATOR_TOOL_CNC_Chisel : FILE
{
	meta:
		description = "Detect binaries using Chisel"
		author = "ditekSHen"
		id = "d126f2c8-655f-564f-ae46-f6bd6385dcac"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L976-L990"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "08c7b2c4725431c1bf85ae8068f4250c98e58890e3b4c97aa9e419e4f487cada"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "chisel-v" ascii
		$s2 = "sendchisel-v" ascii
		$s3 = "<-chiselclosedcookiedomainefenceempty" ascii
		$ws1 = "Sec-WebSocket-Key" ascii
		$ws2 = "Sec-WebSocket-Protocol" ascii
		$ws3 = "Sec-Websocket-Version" ascii
		$ws4 = "Sec-Websocket-Extensions" ascii

	condition:
		uint16(0)==0x5a4d and (1 of ($s*) and 3 of ($ws*))
}
