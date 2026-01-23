
rule ELASTIC_Windows_Trojan_Metasploit_38B8Ceec : FILE MEMORY
{
	meta:
		description = "Identifies the API address lookup function used by metasploit. Also used by other tools (like beacon)."
		author = "Elastic Security"
		id = "38b8ceec-601c-4117-b7a0-74720e26bf38"
		date = "2021-03-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Metasploit.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "8e3bc02661cedb9885467373f8120542bb7fc8b0944803bc01642fbc8426298b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "44b9022d87c409210b1d0807f5a4337d73f19559941660267d63cd2e4f2ff342"
		threat_name = "Windows.Trojan.Metasploit"
		severity = 85
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF 31 C0 AC 3C 61 }

	condition:
		$a1
}
