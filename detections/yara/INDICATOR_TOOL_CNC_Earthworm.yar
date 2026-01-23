import "pe"

rule DITEKSHEN_INDICATOR_TOOL_CNC_Earthworm : FILE
{
	meta:
		description = "Detects Earthworm C&C Windows/macOS tool"
		author = "ditekSHen"
		id = "4a6edcf3-b3c4-5620-8eac-102b1ce425f8"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_tools.yar#L455-L471"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "5045faaaa9e60d4bd506240d51ff78dad4e89ccee0e824e7e5c309a8d3ae2883"
		score = 75
		quality = 50
		tags = "FILE"

	strings:
		$s1 = "lcx_tran 0.0.0.0:%d <--[%4d usec]--> %s:%d" fullword ascii
		$s2 = "ssocksd 0.0.0.0:%d <--[%4d usec]--> socks server" fullword ascii
		$s3 = "rcsocks 0.0.0.0:%d <--[%4d usec]--> 0.0.0.0:%d" fullword ascii
		$s4 = "rssocks %s:%d <--[%4d usec]--> socks server" fullword ascii
		$s5 = "--> %3d <-- (close)used/unused  %d/%d" fullword ascii
		$s6 = "<-- %3d --> (open)used/unused  %d/%d" fullword ascii
		$s7 = "--> %d start server" ascii
		$s8 = "Error on connect %s:%d [proto_init_cmd_rcsocket]" fullword ascii
		$url = "http://rootkiter.com/EarthWrom/" nocase fullword ascii

	condition:
		( uint16(0)==0xfacf or uint16(0)==0x5a4d) and (5 of ($s*) or $url)
}

