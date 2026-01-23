import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_PE_Resourcetuner : FILE
{
	meta:
		description = "Detects executables with modified PE resources using the unpaid version of Resource Tuner"
		author = "ditekSHen"
		id = "2ada52b4-de9e-5b66-a05e-da894ca79e48"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L793-L801"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "25959ba2f974ecdcda624b4b34cd8dac0336af0dd7c88d2e3b17ec94d58b87b8"
		score = 40
		quality = 45
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "Modified by an unpaid evaluation copy of Resource Tuner 2 (www.heaventools.com)" fullword wide

	condition:
		uint16(0)==0x5a4d and all of them
}

