rule JPCERTCC_Elf_Plead
{
	meta:
		description = "ELF_PLEAD"
		author = "JPCERT/CC Incident Response Group"
		id = "12f93939-812f-52b6-9582-b375bb361892"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "https://github.com/JPCERTCC/MalConfScan/"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L515-L529"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		hash = "f704303f3acc2fd090145d5ee893914734d507bd1e6161f82fb34d45ab4a164b"
		logic_hash = "088d17afe77076f8b1e5f7cb285d825d597d9c971a03f878bf64b6d2af14a01f"
		score = 75
		quality = 80
		tags = ""

	strings:
		$ioctl = "ioctl TIOCSWINSZ error"
		$class1 = "CPortForwardManager"
		$class2 = "CRemoteShell"
		$class3 = "CFileManager"
		$lzo = { 81 ?? FF 07 00 00 81 ?? 1F 20 00 00 }

	condition:
		3 of them
}

