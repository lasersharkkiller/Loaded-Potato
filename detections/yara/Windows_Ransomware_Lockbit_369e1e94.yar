
rule ELASTIC_Windows_Ransomware_Lockbit_369E1E94 : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Lockbit (Windows.Ransomware.Lockbit)"
		author = "Elastic Security"
		id = "369e1e94-3fbb-4828-bb78-89d26e008105"
		date = "2022-07-05"
		modified = "2022-07-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Lockbit.yar#L43-L67"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d61af007f6c792b8fb6c677143b7d0e2533394e28c50737588e40da475c040ee"
		logic_hash = "c34dafc024d85902b85fc3424573abb8781d6fab58edd86c255266db3635ce98"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9cf4c112c0ee708ae64052926681e8351f1ccefeb558c41e875dbd9e4bdcb5f2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 66 83 F8 61 72 ?? 66 83 F8 66 77 ?? 66 83 E8 57 EB ?? 66 83 F8 30 72 ?? 66 83 F8 39 77 ?? 66 83 E8 30 EB ?? }
		$a2 = { 8B EC 53 56 57 33 C0 8B 5D ?? 33 C9 33 D2 8B 75 ?? 8B 7D ?? 85 F6 74 ?? 55 8B 6D ?? 8A 54 0D ?? 02 D3 8A 5C 15 ?? 8A 54 1D ?? }
		$a3 = { 53 51 6A ?? 58 0F A2 F7 C1 ?? ?? ?? ?? 0F 95 C0 84 C0 74 ?? 0F C7 F0 0F C7 F2 59 5B C3 6A ?? 58 33 C9 0F A2 F7 C3 ?? ?? ?? ?? 0F 95 C0 84 C0 74 ?? 0F C7 F8 0F C7 FA 59 5B C3 0F 31 8B C8 C1 C9 ?? 0F 31 8B D0 C1 C2 ?? 8B C1 59 5B C3 }
		$b1 = { 6D 00 73 00 65 00 78 00 63 00 68 00 61 00 6E 00 67 00 65 00 00 00 73 00 6F 00 70 00 68 00 6F 00 73 00 }
		$b2 = "LockBit 3.0 the world's fastest and most stable ransomware from 2019" ascii fullword
		$b3 = "http://lockbit"
		$b4 = "Warning! Do not delete or modify encrypted files, it will lead to problems with decryption of files!" ascii fullword

	condition:
		2 of ($a*) or all of ($b*)
}
