import "pe"


rule DITEKSHEN_INDICATOR_TOOL_Fastreverseproxy : FILE
{
	meta:
		description = "Detects Fast Reverse Proxy (FRP) tool"
		author = "ditekSHen"
		id = "d643cc38-a96c-5353-bb46-ca46ea740e3b"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1603-L1619"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "c26d9e8833c7055a03a446eb983c7f70f1f18669d009ebc204dda3f0bb6048f7"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$x1 = "<title>frp client admin UI</title>" ascii
		$x2 = "https://github.com/fatedier/frp" ascii
		$s1 = ").SetLogin" ascii
		$s2 = ").SetPing" ascii
		$s3 = ").SetNewWorkConn" ascii
		$s4 = ").ServeHTTP" ascii
		$s5 = ").Middleware" ascii
		$s6 = "frpc proxy config error:" ascii
		$s7 = "frpc sudp visitor proxy is close" ascii

	condition:
		uint16(0)==0x5a4d and ( all of ($x*) or (1 of ($x*) and 4 of ($s*)) or ( all of ($s*)))
}
