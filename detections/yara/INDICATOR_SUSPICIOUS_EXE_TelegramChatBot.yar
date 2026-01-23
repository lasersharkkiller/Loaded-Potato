import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Telegramchatbot : FILE
{
	meta:
		description = "Detects executables using Telegram Chat Bot"
		author = "ditekSHen"
		id = "bcee52fe-495a-5ea1-bcd9-78b57c992752"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L1291-L1306"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "40374d9dda3d1896906f342725425860e83fbe6b5b0ac656a7035094e36340c0"
		score = 40
		quality = 45
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "https://api.telegram.org/bot" ascii wide
		$s2 = "/sendMessage?chat_id=" fullword ascii wide
		$s3 = "Content-Disposition: form-data; name=\"" fullword ascii
		$s4 = "/sendDocument?chat_id=" fullword ascii wide
		$p1 = "/sendMessage" ascii wide
		$p2 = "/sendDocument" ascii wide
		$p3 = "&chat_id=" ascii wide
		$p4 = "/sendLocation" ascii wide

	condition:
		uint16(0)==0x5a4d and (2 of ($s*) or (2 of ($p*) and 1 of ($s*)))
}

