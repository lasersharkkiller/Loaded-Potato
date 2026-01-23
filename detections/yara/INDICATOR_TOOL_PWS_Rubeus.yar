import "pe"


rule DITEKSHEN_INDICATOR_TOOL_PWS_Rubeus : FILE
{
	meta:
		description = "Detects Rubeus kerberos defensive/offensive toolset"
		author = "ditekSHen"
		id = "5af8cee0-e664-5dfe-9932-0e74ed41b6b4"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L514-L531"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "ee817d23427970d7e77f9ce2a7cbc25c77177d81354fed83e7551cdcbc2d7cd2"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" fullword wide
		$s2 = "(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))" fullword wide
		$s3 = "rc4opsec" fullword wide
		$s4 = "pwdlastset" fullword wide
		$s5 = "LsaEnumerateLogonSessions" fullword ascii
		$s6 = "extractKerberoastHash" fullword ascii
		$s7 = "ComputeAllKerberosPasswordHashes" fullword ascii
		$s8 = "kerberoastDomain" fullword ascii
		$s9 = "GetUsernamePasswordTGT" fullword ascii
		$s10 = "WriteUserPasswordToFile" fullword ascii

	condition:
		uint16(0)==0x5a4d and 8 of them
}
