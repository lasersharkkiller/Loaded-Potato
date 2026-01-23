import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_05Abac07F8D0Ce567F7D75Ee047Efee2 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "17355de3-08a9-585d-bc4f-fd16ff59e2a2"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6323-L6334"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "0196ebd0b5821863c99676907a972e214f46411650fe20557e9f919609d12659"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "68b32eac87652af4172e40e3764477437e5a5ce9"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ultrareach Internet Corp." and pe.signatures[i].serial=="05:ab:ac:07:f8:d0:ce:56:7f:7d:75:ee:04:7e:fe:e2")
}

