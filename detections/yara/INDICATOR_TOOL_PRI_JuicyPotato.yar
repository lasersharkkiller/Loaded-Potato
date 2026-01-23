import "pe"


rule DITEKSHEN_INDICATOR_TOOL_PRI_Juicypotato : FILE
{
	meta:
		description = "Detect JuicyPotato"
		author = "ditekSHen"
		id = "2fb52598-9771-507b-a06d-7b9bc693ffee"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1255-L1270"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "43a7ac16b9633fd2e6c43ca142cd0d0e2166287bb51e1b6344119959fe054c19"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$x1 = "\\JuicyPotato.pdb" ascii
		$x2 = "JuicyPotato v%s" fullword ascii
		$s1 = "hello.stg" fullword wide
		$s2 = "ppVirtualProcessorRoots" fullword ascii
		$s3 = "Lock already taken" fullword ascii
		$s4 = "[+] authresult %d" fullword ascii
		$s5 = "RPC -> send failed with error: %d" fullword ascii
		$s6 = "Priv Adjust FALSE" fullword ascii

	condition:
		uint16(0)==0x5a4d and ( all of ($x*) or (1 of ($x*) and 3 of ($s*)) or (5 of ($s*)))
}
