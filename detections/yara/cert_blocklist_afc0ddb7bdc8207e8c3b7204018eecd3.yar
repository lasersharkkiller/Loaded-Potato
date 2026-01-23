import "pe"

rule REVERSINGLABS_Cert_Blocklist_Afc0Ddb7Bdc8207E8C3B7204018Eecd3 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "73f4d6e2-6924-59fa-8ec1-305f2d5dc5a3"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12236-L12254"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "302e2d6b31ca5c2c33c4ec7294630fd88a9c40f70ddecdc606ccff27b24e1cd4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE9\\x83\\xB4\\xE5\\xB7\\x9E\\xE8\\x9C\\x97\\xE7\\x89\\x9B\\xE7\\xBD\\x91\\xE7\\xBB\\x9C\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and (pe.signatures[i].serial=="00:af:c0:dd:b7:bd:c8:20:7e:8c:3b:72:04:01:8e:ec:d3" or pe.signatures[i].serial=="af:c0:dd:b7:bd:c8:20:7e:8c:3b:72:04:01:8e:ec:d3") and 1629676800<=pe.signatures[i].not_after)
}

