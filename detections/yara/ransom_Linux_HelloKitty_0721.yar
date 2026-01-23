
rule TRELLIX_ARC_Ransom_Linux_Hellokitty_0721 : RANSOMWARE FILE
{
	meta:
		description = "rule to detect Linux variant of the Hello Kitty Ransomware"
		author = "Christiaan @ ATR"
		id = "097b02e7-93d8-5d4f-9964-7b660b3cd7b9"
		date = "2021-07-19"
		modified = "2021-07-19"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_Linux_HelloKitty0721.yar#L1-L28"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "77a3809df4c7c591a855aaecd702af62935952937bb81661aa7f68e64dcf4fb4"
		score = 75
		quality = 70
		tags = "RANSOMWARE, FILE"
		Rule_Version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:Linux/HelloKitty"
		hash1 = "ca607e431062ee49a21d69d722750e5edbd8ffabcb54fa92b231814101756041"
		hash2 = "556e5cb5e4e77678110961c8d9260a726a363e00bf8d278e5302cb4bfccc3eed"

	strings:
		$v1 = "esxcli vm process kill -t=force -w=%d" fullword ascii
		$v2 = "esxcli vm process kill -t=hard -w=%d" fullword ascii
		$v3 = "esxcli vm process kill -t=soft -w=%d" fullword ascii
		$v4 = "error encrypt: %s rename back:%s" fullword ascii
		$v5 = "esxcli vm process list" fullword ascii
		$v6 = "Total VM run on host:" fullword ascii
		$v7 = "error lock_exclusively:%s owner pid:%d" fullword ascii
		$v8 = "Error open %s in try_lock_exclusively" fullword ascii
		$v9 = "Mode:%d  Verbose:%d Daemon:%d AESNI:%d RDRAND:%d " fullword ascii
		$v10 = "pthread_cond_signal() error" fullword ascii
		$v11 = "ChaCha20 for x86_64, CRYPTOGAMS by <appro@openssl.org>" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <200KB and (8 of them )) or ( all of them )
}
