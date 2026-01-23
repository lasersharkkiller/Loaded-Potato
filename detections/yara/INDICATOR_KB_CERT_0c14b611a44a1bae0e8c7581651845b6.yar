import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0C14B611A44A1Bae0E8C7581651845B6 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "a6ebe304-e896-5cb3-8a49-ebffe0525601"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L380-L391"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "dae6318cf6f8e33e11af5c4b06379f8ef2744e784bb793c78f782b6a6286b84b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c3288c7fbb01214c8f2dc3172c3f5c48f300cb8b"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NEEDCODE SP Z O O" and pe.signatures[i].serial=="0c:14:b6:11:a4:4a:1b:ae:0e:8c:75:81:65:18:45:b6")
}

