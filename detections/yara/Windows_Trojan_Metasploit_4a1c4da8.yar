
rule ELASTIC_Windows_Trojan_Metasploit_4A1C4Da8 : FILE MEMORY
{
	meta:
		description = "Identifies Metasploit 64 bit reverse tcp shellcode."
		author = "Elastic Security"
		id = "4a1c4da8-837d-4ad1-a672-ddb8ba074936"
		date = "2021-06-10"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Metasploit.yar#L187-L206"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9582d37ed9de522472abe615dedef69282a40cfd58185813c1215249c24bbf22"
		logic_hash = "9d3a3164ed1019dcb557cf20734a81be9964a555ddb2e0104f7202880b2ed177"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7a31ce858215f0a8732ce6314bfdbc3975f1321e3f87d7f4dc5a525f15766987"
		threat_name = "Windows.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 6A 10 56 57 68 99 A5 74 61 FF D5 85 C0 74 0A FF 4E 08 }

	condition:
		all of them
}
