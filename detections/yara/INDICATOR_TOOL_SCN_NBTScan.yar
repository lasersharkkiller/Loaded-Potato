import "pe"


rule DITEKSHEN_INDICATOR_TOOL_SCN_Nbtscan : FILE
{
	meta:
		description = "Detects NBTScan scanner for open NETBIOS nameservers on a local or remote TCP/IP network"
		author = "ditekSHen"
		id = "663c324e-4784-5efe-bbdf-60fa42e13944"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L402-L420"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "a81b95ad60aac4d66586ae7dc61f6bcbe2b7185b66b2bb895f45abff3ad3f430"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "[%s] is an invalid target (bad IP/hostname)" fullword ascii
		$s2 = "ERROR: no parse for %s -- %s" fullword ascii
		$s3 = "add_target failed" fullword ascii
		$s4 = "   -p <n>    bind to UDP Port <n> (default=%d)" fullword ascii
		$s5 = "process_response.c" fullword ascii
		$s6 = "currTarget != 0" fullword ascii
		$s7 = "parse_target.c" fullword ascii
		$s8 = "dump_packet.c" fullword ascii
		$s9 = "parse_target_cb.c" fullword ascii
		$s10 = "DUMP OF PACKET" fullword ascii
		$s11 = "lookup_hostname.c" fullword ascii

	condition:
		uint16(0)==0x5a4d and 10 of ($s*)
}
