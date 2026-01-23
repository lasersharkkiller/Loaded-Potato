import "pe"


rule RUSSIANPANDA_Metastealer_NET_Reactor_Packer : FILE
{
	meta:
		description = "Detects NET_Reactor_packer 12-2023 used in MetaStealer"
		author = "RussianPanda"
		id = "5d4f62d2-6a27-53af-9b03-61daa99c10a4"
		date = "2023-12-29"
		modified = "2023-12-30"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/MetaStealer/metastealer_12-2023_packer.yar#L1-L16"
		license_url = "N/A"
		logic_hash = "1951d8b05f11b8a77a5bf792ad2b0ad95b8dede936ab5cd0699383468c3c97a8"
		score = 75
		quality = 83
		tags = "FILE"

	strings:
		$s1 = {C7 84 24 80 02 00 00 24 02 00 00 C6 44 24}
		$s2 = "mscoree.dll" wide
		$s3 = {43 61 76 69 6c 73 20 43 6f 72 70 2e 20 32 30 31 30}
		$s4 = {80 F1 E7 80 F2 44 [16] 80 F1 4B 80 F2 23}

	condition:
		3 of ($s*) and filesize <600KB
}
