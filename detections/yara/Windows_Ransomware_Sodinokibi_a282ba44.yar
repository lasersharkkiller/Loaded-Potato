
rule ELASTIC_Windows_Ransomware_Sodinokibi_A282Ba44 : BETA FILE MEMORY
{
	meta:
		description = "Identifies SODINOKIBI/REvil ransomware"
		author = "Elastic Security"
		id = "a282ba44-b8bf-4fcc-a1c4-795675a928de"
		date = "2020-06-18"
		modified = "2021-08-23"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.revil"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Sodinokibi.yar#L64-L91"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "3a583069c9ab851a90f3a61c9c4fa67f8b918b8d168fcf7f25b2a3ae3465c596"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "07f1feb22f8b9de0ebd5c4649545eb4823a274b49b2c61a44d3eed4739ecd572"
		threat_name = "Windows.Ransomware.Sodinokibi"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$c1 = { 59 59 85 F6 74 25 8B 55 08 83 66 04 00 89 3E 8B 0A 0B 4A 04 }
		$c2 = { 8D 45 F8 89 75 FC 50 8D 45 FC 89 75 F8 50 56 56 6A 01 6A 30 }
		$c3 = { 75 0C 72 D3 33 C0 40 5F 5E 5B 8B E5 5D C3 33 C0 EB F5 55 8B EC 83 }
		$c4 = { 0C 8B 04 B0 83 78 04 05 75 1C FF 70 08 FF 70 0C FF 75 0C FF }
		$c5 = { FB 8B 45 FC 50 8B 08 FF 51 08 5E 8B C7 5F 5B 8B E5 5D C3 55 }
		$c6 = { BC 00 00 00 33 D2 8B 4D F4 8B F1 8B 45 F0 0F A4 C1 01 C1 EE 1F }
		$c7 = { 54 8B CE F7 D1 8B C2 23 4D DC F7 D0 33 4D F4 23 C7 33 45 E8 89 }
		$c8 = { 0C 89 46 0C 85 C0 75 2A 33 C0 EB 6C 8B 46 08 85 C0 74 62 6B }

	condition:
		(6 of ($c*))
}
