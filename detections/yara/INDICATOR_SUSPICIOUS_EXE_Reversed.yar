import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Reversed : FILE
{
	meta:
		description = "Detects reversed executables. Observed N-stage drop"
		author = "ditekSHen"
		id = "765b1983-8831-5f7d-9cbd-90af0cd452f7"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L2125-L2133"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "4d031f59b201f5c5c9b69bbbe277cc10c3b5ed8427c5c2f679fdd33c8bc41501"
		score = 40
		quality = 45
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "edom SOD ni nur eb tonnac margorp sihT" ascii

	condition:
		uint16( filesize -0x2)==0x4d5a and $s1
}

