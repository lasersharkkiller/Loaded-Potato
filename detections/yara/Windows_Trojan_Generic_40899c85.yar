
rule ELASTIC_Windows_Trojan_Generic_40899C85 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Generic (Windows.Trojan.Generic)"
		author = "Elastic Security"
		id = "40899c85-bb49-412c-8081-3a1359957c52"
		date = "2023-12-15"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Generic.yar#L240-L260"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "88eb4f2e7085947bfbd03c69573fdca0de4a74bab844f09ecfcf88e358af20cc"
		logic_hash = "317034add0343baa26548712de8b2acc04946385fbee048cea0bd8d7ae642b36"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d02a17a3b9efc2fd991320a5db7ab2384f573002157cddcd12becf137e893bd8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "_sqlDataTypeSize"
		$a2 = "ChromeGetName"
		$a3 = "get_os_crypt"

	condition:
		all of them
}
