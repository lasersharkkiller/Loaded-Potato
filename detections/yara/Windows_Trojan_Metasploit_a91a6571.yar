
rule ELASTIC_Windows_Trojan_Metasploit_A91A6571 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Metasploit (Windows.Trojan.Metasploit)"
		author = "Elastic Security"
		id = "a91a6571-ae2d-4ab4-878b-38b455f42c01"
		date = "2022-06-08"
		modified = "2022-09-29"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Metasploit.yar#L228-L246"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ff7795edff95a45b15b03d698cbdf70c19bc452daf4e2d5e86b2bbac55494472"
		logic_hash = "cc59320ba9f8907d1d9b9dc120d8b4807b419e49c55be1fd5d2cdbb0c5d4e5cc"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e372484956eab80e4bf58f4ae1031de705cb52eaefa463aa77af7085c463638d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { FC 48 83 E4 F0 E8 CC 00 00 00 41 51 41 50 52 48 31 D2 51 56 65 48 8B 52 60 48 8B 52 18 48 8B 52 }

	condition:
		all of them
}
