import "pe"

rule REVERSINGLABS_Cert_Blocklist_08D4Dc90047B8470Ccaf3924Dfbd8B5F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2abe218a-1d93-5efe-9878-4314cf9ecdf7"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11668-L11684"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "569db2f6d6f4da9985c57812a03f91bce88f2150b17659249e0f746a0d15150b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Dibies" and pe.signatures[i].serial=="08:d4:dc:90:04:7b:84:70:cc:af:39:24:df:bd:8b:5f" and 1619136000<=pe.signatures[i].not_after)
}

