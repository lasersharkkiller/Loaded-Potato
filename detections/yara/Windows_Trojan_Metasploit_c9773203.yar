
rule ELASTIC_Windows_Trojan_Metasploit_C9773203 : FILE MEMORY
{
	meta:
		description = "Identifies the 64 bit API hashing function used by Metasploit. This has been re-used by many other malware families."
		author = "Elastic Security"
		id = "c9773203-6d1e-4246-a1e0-314217e0207a"
		date = "2021-04-07"
		modified = "2021-08-23"
		reference = "https://github.com/rapid7/metasploit-framework/blob/04e8752b9b74cbaad7cb0ea6129c90e3172580a2/external/source/shellcode/windows/x64/src/block/block_api.asm"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Metasploit.yar#L121-L140"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "1d6503ccf05b8e8b4368ed0fb2e57aa2be94151ce7e2445b5face7b226a118e9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "afde93eeb14b4d0c182f475a22430f101394938868741ffa06445e478b6ece36"
		threat_name = "Windows.Trojan.Metasploit"
		severity = 10
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 48 31 C0 AC 41 C1 C9 0D 41 01 C1 38 E0 75 F1 4C 03 4C 24 08 45 39 D1 }

	condition:
		all of them
}
