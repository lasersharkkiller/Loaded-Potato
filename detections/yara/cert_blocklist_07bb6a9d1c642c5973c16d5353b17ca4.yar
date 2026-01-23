import "pe"

rule REVERSINGLABS_Cert_Blocklist_07Bb6A9D1C642C5973C16D5353B17Ca4 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "094a02ee-394b-5989-9f73-6b942aca5500"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5770-L5786"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b98dcd4f0ebe870a9dad55cac5b0db81be6062216337b75a74a0aff8436df57f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MADAS d.o.o." and pe.signatures[i].serial=="07:bb:6a:9d:1c:64:2c:59:73:c1:6d:53:53:b1:7c:a4" and 1601856001<=pe.signatures[i].not_after)
}

