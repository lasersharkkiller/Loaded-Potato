import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_07Bb6A9D1C642C5973C16D5353B17Ca4 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "a29590bb-d8f9-5842-81bd-f9a9f7cea642"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L354-L365"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "faecdcd78bc60f730bfe5a049fd0bd1309b44d185c0cbc81dfc326a162d5fcb2"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "9de562e98a5928866ffc581b794edfbc249a2a07"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MADAS d.o.o." and pe.signatures[i].serial=="07:bb:6a:9d:1c:64:2c:59:73:c1:6d:53:53:b1:7c:a4")
}

