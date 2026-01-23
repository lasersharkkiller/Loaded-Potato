
rule ELASTIC_Windows_Trojan_Emotet_8B9449C1 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Emotet (Windows.Trojan.Emotet)"
		author = "Elastic Security"
		id = "8b9449c1-41a3-4f4d-b654-6921f2742b9a"
		date = "2022-11-09"
		modified = "2022-12-20"
		reference = "https://www.elastic.co/security-labs/emotet-dynamic-configuration-extraction"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Emotet.yar#L146-L166"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ffac0120c3ae022b807559e8ed7902fde0fa5f7cb9c5c8d612754fa498288572"
		logic_hash = "5501354ebc1d97fe5ce894d5907adb29440f557f2dd235e1e983ae2d109199a2"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ff15cec5eb41bb9637b570d717151cdc076e88a7b4c3d1c31157d41fe7569318"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$hash_1 = { 8B CB 41 8B D0 D3 E2 41 8B CB D3 E0 03 D0 41 0F BE ?? 03 D0 41 2B D0 49 FF ( C1 | C2 ) }
		$hash_2 = { 44 8B ?? 44 8B ?? 41 8B CB 41 D3 ?? 8B CB D3 E0 8B C8 8D 42 ?? 66 83 F8 ?? 0F B7 C2 77 ?? 83 C0 ?? 41 2B ?? 41 03 ?? 03 C1 49 83 ?? ?? 41 0F B7 }

	condition:
		any of them
}
