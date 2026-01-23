
rule VOLEXITY_Webshell_Jsp_Godzilla : WEBSHELLS COMMODITY
{
	meta:
		description = "Detects the JSP implementation of the Godzilla Webshell."
		author = "threatintel@volexity.com"
		id = "47c8eab8-84d7-5566-b757-5a6dcc7579b7"
		date = "2021-11-08"
		modified = "2022-08-10"
		reference = "https://unit42.paloaltonetworks.com/manageengine-godzilla-nglite-kdcsponge/"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2022/2022-08-10 Mass exploitation of (Un)authenticated Zimbra RCE CVE-2022-27925/yara.yar#L1-L28"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "52cba9545f662da18ca6e07340d7a9be637b89e7ed702dd58cac545c702a00e3"
		score = 75
		quality = 80
		tags = "WEBSHELLS, COMMODITY"
		hash1 = "2786d2dc738529a34ecde10ffeda69b7f40762bf13e7771451f13a24ab7fc5fe"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		memory_suitable = 1

	strings:
		$s1 = ".getWriter().write(base64Encode(" wide ascii
		$s2 = ".getAttribute(" ascii wide
		$s3 = "java.security.MessageDigest" ascii wide
		$auth1 = /String xc=\"[a-f0-9]{16}\"/ ascii wide
		$auth2 = "String pass=\"" ascii wide
		$magic = "class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q"
		$magic2 = "<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class"

	condition:
		all of ($s*) or all of ($auth*) or any of ($magic*)
}
