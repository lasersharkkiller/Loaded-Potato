rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Ransomwareexx
{
	meta:
		description = "Detects files referencing identities associated with RansomwareEXX Linux ransomware"
		author = "ditekShen"
		id = "dfcff8cb-c50c-559e-b5b9-8c2cdac7a3dc"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_id.yar#L142-L150"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "a83ada5d29c6d62a292c4b3a1379558cddcaf63d97dbdfc6afd27cc52f6f656d"
		score = 75
		quality = 73
		tags = ""

	strings:
		$s1 = "france.eigs@protonmail.com" ascii wide nocase

	condition:
		any of them
}

