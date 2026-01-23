
rule ELASTIC_Windows_Trojan_Metasploit_7Bc0F998 : FILE MEMORY
{
	meta:
		description = "Identifies the API address lookup function leverage by metasploit shellcode"
		author = "Elastic Security"
		id = "7bc0f998-7014-4883-8a56-d5ee00c15aed"
		date = "2021-03-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Metasploit.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "29cb48086dbcd48bd83c5042ed78370e127e1ea5170ee7383b88659b31e896b5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fdb5c665503f07b2fc1ed7e4e688295e1222a500bfb68418661db60c8e75e835"
		threat_name = "Windows.Trojan.Metasploit"
		severity = 84
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 48 31 D2 65 48 8B 52 60 48 8B 52 18 48 8B 52 20 48 8B 72 50 48 0F B7 4A 4A 4D 31 C9 48 31 C0 AC 3C 61 }

	condition:
		$a1
}
