rule BINARYALERT_Hacktool_Multi_Responder_Py
{
	meta:
		description = "Responder is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server"
		author = "@fusionrace"
		id = "82699a67-8ba1-5535-9183-3c857e60134c"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "http://www.c0d3xpl0it.com/2017/02/compromising-domain-admin-in-internal-pentest.html"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/multi/hacktool_multi_responder_py.yara#L1-L17"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "a99a806b7c578af1f2163583f957db13fa7269c7426666189d85bec2ac87ad4b"
		score = 75
		quality = 80
		tags = ""

	strings:
		$s1 = "Poison all requests with another IP address than Responder's one." fullword ascii wide
		$s2 = "Responder is in analyze mode. No NBT-NS, LLMNR, MDNS requests will be poisoned." fullword ascii wide
		$s3 = "Enable answers for netbios wredir suffix queries. Answering to wredir will likely break stuff on the network." fullword ascii wide
		$s4 = "This option allows you to fingerprint a host that issued an NBT-NS or LLMNR query." fullword ascii wide
		$s5 = "Upstream HTTP proxy used by the rogue WPAD Proxy for outgoing requests (format: host:port)" fullword ascii wide
		$s6 = "31mOSX detected, -i mandatory option is missing" fullword ascii wide
		$s7 = "This option allows you to fingerprint a host that issued an NBT-NS or LLMNR query." fullword ascii wide

	condition:
		any of them
}

