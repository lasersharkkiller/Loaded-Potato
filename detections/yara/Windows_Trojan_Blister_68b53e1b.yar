
rule ELASTIC_Windows_Trojan_Blister_68B53E1B : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Blister (Windows.Trojan.Blister)"
		author = "Elastic Security"
		id = "68b53e1b-dbd7-4903-ac10-8336c05f42df"
		date = "2023-08-02"
		modified = "2023-08-08"
		reference = "https://www.elastic.co/security-labs/elastic-security-uncovers-blister-malware-campaign"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Blister.yar#L46-L66"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5fc79a4499bafa3a881778ef51ce29ef015ee58a587e3614702e69da304395db"
		logic_hash = "6d935461406a6b9b39867d52aa5ecb088945ae0f8c56895a67e8565e5a2a3699"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b46d59117eda3d6a7a6397287c962106719bf338d19814e20bde9deeebfe65c1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$b_loader_xor = { 48 8B C3 49 03 DC 83 E0 03 8A 44 05 48 [2-3] ?? 03 ?? 4D 2B ?? 75 }
		$b_loader_virtual_protect = { 48 8D 45 50 41 ?? ?? ?? ?? 00 4C 8D ?? 04 4C 89 ?? ?? 41 B9 04 00 00 00 4C 89 ?? F0 4C 8D 45 58 48 89 44 24 20 48 8D 55 F0 }

	condition:
		all of them
}
