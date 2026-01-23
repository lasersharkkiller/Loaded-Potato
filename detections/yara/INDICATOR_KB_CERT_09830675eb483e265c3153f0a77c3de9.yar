import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_09830675Eb483E265C3153F0A77C3De9 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "3370886e-6866-598b-b3bf-29c7f2537425"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L328-L339"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "b0a504ed2a2816602ac378a700567909812650f409626a7b2c1e25cf7f8cb51c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "1bb5503a2e1043616b915c4fce156c34304505d6"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "James LTH d.o.o." and pe.signatures[i].serial=="09:83:06:75:eb:48:3e:26:5c:31:53:f0:a7:7c:3d:e9")
}

