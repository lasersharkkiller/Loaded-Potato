import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_020Bc03538Fbdc792F39D99A24A81B97 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "d5fd84b4-cccf-569d-96ea-26d9d21c6adf"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L302-L313"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "154d7d814ff0b1c2d85557211dd68d0bd82e9953a9912ac3c26475a1316b0cb3"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0ab2629e4e721a65ad35758d1455c1202aa643d3"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "GLOBAL PARK HORIZON SP Z O O" and pe.signatures[i].serial=="02:0b:c0:35:38:fb:dc:79:2f:39:d9:9a:24:a8:1b:97")
}

