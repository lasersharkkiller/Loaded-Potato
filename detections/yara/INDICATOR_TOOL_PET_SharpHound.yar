import "pe"

rule DITEKSHEN_INDICATOR_TOOL_PET_Sharphound : FILE
{
	meta:
		description = "Detects BloodHound"
		author = "ditekSHen"
		id = "d8f44e15-3e7c-5e5d-9d74-30c61e679fcb"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_tools.yar#L556-L573"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "bdf10d0aabd6c41e8dd1f87c0fa141f300d785146d059fcd301ec35f65fbe990"
		score = 75
		quality = 48
		tags = "FILE"

	strings:
		$id1 = "InvokeBloodHound" fullword ascii
		$id2 = "Sharphound" ascii nocase
		$s1 = "SamServerExecute" fullword ascii
		$s2 = "get_RemoteDesktopUsers" fullword ascii
		$s3 = "commandline.dll.compressed" ascii wide
		$s4 = "operatingsystemservicepack" fullword wide
		$s5 = "LDAP://" fullword wide
		$s6 = "wkui1_logon_domain" fullword ascii
		$s7 = "GpoProps" fullword ascii
		$s8 = "a517a8de-5834-411d-abda-2d0e1766539c" fullword ascii nocase

	condition:
		uint16(0)==0x5a4d and ( all of ($id*) or 6 of ($s*) or (1 of ($id*) and 4 of ($s*)))
}

