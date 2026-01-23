
rule ELASTIC_Windows_Trojan_Metasploit_A6E956C9 : FILE MEMORY
{
	meta:
		description = "Identifies the API address lookup function leverage by metasploit shellcode"
		author = "Elastic Security"
		id = "a6e956c9-799e-49f9-b5c5-ac68aaa2dc21"
		date = "2021-03-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Metasploit.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "fb4e3e54618075d5ef6ec98d1ba9c332ce9f677f0879e07b34a2ca08b2180dd9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "21855599bc51ec2f71d694d4e0f866f815efe54a42842dfe5f8857811530a686"
		threat_name = "Windows.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 60 89 E5 31 C0 64 8B 50 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF AC 3C 61 7C 02 2C 20 }

	condition:
		$a1
}
