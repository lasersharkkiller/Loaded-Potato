rule RAT_njRat
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects njRAT"
		reference = "http://malwareconfig.com/stats/njRat"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "6289b9c8-eef6-5cfb-97bd-b819158d6fdd"
	strings:
		$s1 = {7C 00 27 00 7C 00 27 00 7C} // |'|'|
		$s2 = "netsh firewall add allowedprogram" wide
		$s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
		$s4 = "yyyy-MM-dd" wide

		$v1 = "cmd.exe /k ping 0 & del" wide
		$v2 = "cmd.exe /c ping 127.0.0.1 & del" wide
		$v3 = "cmd.exe /c ping 0 -n 2 & del" wide

	condition:
		all of ($s*) and any of ($v*)
}

