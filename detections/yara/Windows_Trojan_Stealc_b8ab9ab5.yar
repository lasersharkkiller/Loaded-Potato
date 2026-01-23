
rule ELASTIC_Windows_Trojan_Stealc_B8Ab9Ab5 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Stealc (Windows.Trojan.Stealc)"
		author = "Elastic Security"
		id = "b8ab9ab5-5731-4651-b982-03ad8fe347fb"
		date = "2024-03-13"
		modified = "2024-03-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Stealc.yar#L1-L27"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0d1c07c84c54348db1637e21260dbed09bd6b7e675ef58e003d0fe8f017fd2c8"
		logic_hash = "5fc5d5cea481d1d204d1aa6c52679a23eb59438df2fe547d14c00524772867bb"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "49253b1d1e39ba25b2d3b622d00633b9629715e65e1537071b0f3b0318b7db12"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$seq_str_decrypt = { 55 8B EC 83 EC ?? 8D 4D ?? E8 ?? ?? ?? ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 83 C0 ?? 50 }
		$seq_lang_check = { 81 E9 19 04 00 00 89 4D ?? 83 7D ?? ?? 77 ?? 8B 55 ?? 0F B6 82 ?? ?? ?? ?? FF 24 85 ?? ?? ?? ?? }
		$seq_mem_check_constant = { 72 09 81 7D F8 57 04 00 00 73 08 }
		$seq_hwid_algo = { 8B 08 69 C9 0B A3 14 00 81 E9 51 75 42 69 8B 55 08 }
		$str1 = "- Country: ISO?" ascii fullword
		$str2 = "%d/%d/%d %d:%d:%d" ascii fullword
		$str3 = "%08lX%04lX%lu" ascii fullword
		$str4 = "\\Outlook\\accounts.txt" ascii fullword
		$str5 = "/c timeout /t 5 & del /f /q" ascii fullword

	condition:
		(2 of ($seq*) or 4 of ($str*))
}
