import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_Usndeletejournal : FILE
{
	meta:
		description = "Detects executables containing anti-forensic artifacts of deleting USN change journal. Observed in ransomware"
		author = "ditekSHen"
		id = "eafc7ed9-d0e7-562d-8215-6f3feddee27a"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L612-L628"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "1920fc2bc8c3628016bb91403960f5fbb101b5822f553c1f28d9502841a9832c"
		score = 40
		quality = 35
		tags = "FILE"
		importance = 20

	strings:
		$cmd1 = "fsutil.exe" ascii wide nocase
		$s1 = "usn deletejournal /D C:" ascii wide nocase
		$s2 = "fsutil.exe usn deletejournal" ascii wide nocase
		$s3 = "fsutil usn deletejournal" ascii wide nocase
		$s4 = "fsutil file setZeroData offset=0" ascii wide nocase
		$ne1 = "fsutil usn readdata C:\\Temp\\sample.txt" wide
		$ne2 = "fsutil transaction query {0f2d8905-6153-449a-8e03-7d3a38187ba1}" wide
		$ne3 = "fsutil resource start d:\\foobar d:\\foobar\\LogDir\\LogBLF::TxfLog d:\\foobar\\LogDir\\LogBLF::TmLog" wide
		$ne4 = "fsutil objectid query C:\\Temp\\sample.txt" wide

	condition:
		uint16(0)==0x5a4d and ( not any of ($ne*) and ((1 of ($cmd*) and 1 of ($s*)) or 1 of ($s*)))
}

