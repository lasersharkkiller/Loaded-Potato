import "pe"


rule DITEKSHEN_INDICATOR_TOOL_Ngrok : FILE
{
	meta:
		description = "Detects Ngrok"
		author = "ditekSHen"
		id = "fc0a0de8-b68b-5b6b-a222-bbc031ebabd3"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1405-L1418"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "f4bba142652aaf77e5b7c123b743cf165ae17210c39cf65b7311f7e7bd91f7e1"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "dashboard.ngrok.com" ascii
		$s2 = "go.ngrok.com/cmd/ngrok/main.go" ascii
		$s3 = "ngrok agent" ascii
		$s4 = "*ngrok.clientInfo" ascii
		$s5 = "'%s'  socket: '%s'  port: %d/edges/https/{{ .EdgeID }}/routes/{{ .ID }}/webhook_" ascii
		$s6 = "/{{ .ID }}/tunnel_sessions/{{ .ID }}/restart" ascii

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0x457f or uint16(0)==0xfacf) and (3 of them )
}
