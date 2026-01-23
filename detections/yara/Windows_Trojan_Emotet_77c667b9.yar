
rule ELASTIC_Windows_Trojan_Emotet_77C667B9 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Emotet (Windows.Trojan.Emotet)"
		author = "Elastic Security"
		id = "77c667b9-6895-428f-8735-ba5853d9484d"
		date = "2022-11-07"
		modified = "2022-12-20"
		reference = "https://www.elastic.co/security-labs/emotet-dynamic-configuration-extraction"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Emotet.yar#L116-L144"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ffac0120c3ae022b807559e8ed7902fde0fa5f7cb9c5c8d612754fa498288572"
		logic_hash = "f11769fe5e9789b451e8826c5fd22bde5b3eb9f7af1d5fec7eec71700fc1f482"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f8fac966f77cd8d6654b8abffbf63d884bd9f0b5d51bfc252004a0d9bd569068"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$c2_list_1 = { 8B 4B ?? 8B 85 ?? ?? ?? ?? 48 FF C1 48 C1 E1 ?? 89 04 19 8B 43 ?? 8B 8D ?? ?? ?? ?? 48 C1 E0 ?? C1 E9 ?? 66 89 4C 18 ?? }
		$c2_list_2 = { 8B 43 ?? 48 8D 0C 80 8B 44 24 ?? 89 44 CB ?? 8B 43 ?? 8B 54 24 ?? 48 8D 0C 80 C1 EA ?? 66 89 54 CB ?? 8B 43 ?? 0F B7 54 24 ?? 48 8D 0C 80 89 54 CB ?? FF 43 ?? }
		$c2_list_3 = { 8B 43 ?? 48 FF C0 48 8D 0C 40 8B 85 ?? ?? ?? ?? 48 03 C9 89 04 CB 8B 43 ?? 8B 95 ?? ?? ?? ?? 48 8D 0C 40 C1 EA ?? 48 03 C9 66 89 54 CB ?? 8B 43 ?? 0F B7 95 ?? ?? ?? ?? 48 8D 0C 40 B8 ?? ?? ?? ?? 48 03 C9 89 54 CB ?? FF 43 ?? }
		$c2_list_4 = { 8B 43 ?? 48 FF C0 48 8D 0C 40 8B 44 24 ?? 89 04 CB 8B 43 ?? 8B 54 24 ?? 48 8D 0C 40 C1 EA ?? 66 89 54 CB ?? 8B 43 ?? 0F B7 54 24 ?? 48 8D 0C 40 89 54 CB ?? FF 43 ?? }
		$c2_list_5 = { 8B 83 ?? ?? ?? ?? 48 8D 0C 80 8B 44 24 ?? 89 44 CB ?? 8B 83 ?? ?? ?? ?? 8B 54 24 ?? 48 8D 0C 80 C1 EA ?? 66 89 54 CB ?? 8B 83 ?? ?? ?? ?? 0F B7 54 24 ?? 48 8D 0C 80 89 14 CB FF 83 ?? ?? ?? ?? }
		$c2_list_a = { 8B 83 ?? ?? ?? ?? 83 F8 ?? 73 ?? 48 8D 4C 24 ?? FF 54 C4 ?? 83 7C 24 ?? ?? 74 ?? 83 7C 24 ?? ?? 74 ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? }
		$string_w_1 = { 8B 0B 49 FF C3 48 8D 5B ?? 33 CD 0F B6 C1 66 41 89 00 0F B7 C1 C1 E9 ?? 66 C1 E8 ?? 4D 8D 40 ?? 66 41 89 40 ?? 0F B6 C1 66 C1 E9 ?? 66 41 89 40 ?? 66 41 89 48 ?? 4D 3B D9 72 ?? }
		$string_w_2 = { 8B CD 49 FF C3 33 0B 48 8D 5B ?? 0F B6 C1 66 41 89 00 0F B7 C1 C1 E9 ?? 66 C1 E8 ?? 4D 8D 40 ?? 66 41 89 40 ?? 0F B6 C1 66 C1 E9 ?? 66 41 89 40 ?? 66 41 89 48 ?? 4D 3B D9 72 ?? }
		$string_a_1 = { 8B 0B 49 FF C3 48 8D 5B ?? 33 CD 41 88 08 0F B7 C1 C1 E9 ?? 66 C1 E8 ?? 4D 8D 40 ?? 41 88 40 ?? 41 88 48 ?? 66 C1 E9 ?? 41 88 48 ?? 4D 3B D9 72 ?? }
		$key_1 = { 45 33 C9 4C 8B D0 48 85 C0 74 ?? 48 8D ?? ?? 4C 8B ?? 48 8B ?? 48 2B ?? 48 83 ?? ?? 48 C1 ?? ?? 48 3B ?? 49 0F 47 ?? 48 85 ?? 74 ?? 48 2B D8 42 8B 04 03 }

	condition:
		(1 of ($string_*)) and (($key_1 or (1 of ($c2_list*))) or (1 of ($c2_list*)))
}
