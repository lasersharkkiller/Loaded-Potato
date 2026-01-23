
rule ELASTIC_Windows_Trojan_Qbot_1Ac22A26 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Qbot (Windows.Trojan.Qbot)"
		author = "Elastic Security"
		id = "1ac22a26-ec88-4e88-8fe6-a092bbb61904"
		date = "2022-12-29"
		modified = "2023-02-01"
		reference = "https://www.elastic.co/security-labs/exploring-the-qbot-attack-pattern"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Qbot.yar#L99-L136"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c2ba065654f13612ae63bca7f972ea91c6fe97291caeaaa3a28a180fb1912b3a"
		logic_hash = "d9beaf4a8c28a0b3c38dda6bf22a96b8c96ef715bd36de880504a9f970338fe2"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "22436c48bc775284d1f682eaeb650fd998302021342efc322c4ca40dd30f1a0d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "qbot" wide
		$a2 = "stager_1.obf\\Benign\\mfc" wide
		$a3 = "common.obf\\Benign\\mfc" wide
		$a4 = "%u;%u;%u"
		$a5 = "%u.%u.%u.%u.%u.%u.%04x"
		$a6 = "%u&%s&%u"
		$a7 = "mnjhuiv40"
		$a8 = "\\u%04X"
		$get_string1 = { 33 D2 8B ?? 6A ?? 5? F7 ?? 8B ?? 08 8A 04 ?? 8B 55 ?? 8B ?? 10 3A 04 }
		$get_string2 = { 8B C6 83 E0 ?? 8A 04 08 3A 04 1E 74 ?? 46 3B F2 72 }
		$get_string3 = { 8A 04 ?? 32 04 ?? 88 04 ?? 4? 83 ?? 01 }
		$set_key_1 = { 8D 87 00 04 00 00 50 56 E8 [4] 59 8B D0 8B CE E8 }
		$set_key_2 = { 59 6A 14 58 6A 0B 66 89 87 [0-1] 20 04 00 00 }
		$cccp_keyboard_0 = { 6A ?? 66 89 45 E? 58 6A ?? 66 89 45 E? 58 }
		$cccp_keyboard_1 = { 66 8B 84 9? ?? FE FF FF B9 FF 03 00 00 66 23 C1 33 ?? 0F B7 }
		$execute_each_tasks = { 8B 0D [4] 83 7C 0E 04 00 74 ?? 83 7C 0E 1C 00 74 ?? 8B 04 0E 85 C0 7E ?? 6B C0 3C }
		$generate_random_alpha_num_string = { 57 E8 [4] 48 50 8D 85 [4] 6A 00 50 E8 [4] 8B 4D ?? 83 C4 10 8A 04 38 88 04 0E 46 83 FE 0C }
		$load_and_inject_b64_dll_from_file = { 6B 45 FC 18 8B 4D F8 83 7C 01 04 00 76 ?? 6A 00 6B 45 FC 18 8B 4D F8 FF 74 01 10 6B 45 FC 18 }
		$decipher_rsrc_data = { F6 86 38 04 00 00 04 89 BE 2C 04 00 00 89 BE 28 04 00 00 [2-6] 8B 0B 8D 45 F? 83 65 F? 00 8B D7 50 E8 }

	condition:
		6 of them
}
