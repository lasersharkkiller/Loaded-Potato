import "pe"


rule DITEKSHEN_INDICATOR_RMM_Connectwise_Screenconnect : FILE
{
	meta:
		description = "Detects ConnectWise Control (formerly ScreenConnect). Review RMM Inventory"
		author = "ditekSHen"
		id = "d752b7e4-b595-56cb-97f1-a60e73160e5a"
		date = "2023-11-16"
		modified = "2023-11-16"
		reference = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_rmm.yar#L62-L83"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "43003f97c33c631a2806ce2b82b2367d2452ceb21b0267b5dfe78b350b66924a"
		score = 75
		quality = 75
		tags = "FILE"
		clamav1 = "INDICATOR.Win.RMM.ConnectWise-ScreenConnect"

	strings:
		$s1 = "FILESYSCREENCONNECT.CORE, VERSION=" wide
		$s2 = "feedback.screenconnect.com/Feedback.axd" wide
		$s3 = /ScreenConnect (Software|Client)/ wide
		$s4 = "ScreenConnect.InstallerActions!ScreenConnect." wide
		$s5 = "\\\\.\\Pipe\\TerminalServer\\SystemExecSrvr\\" wide
		$s6 = "\\jmorgan\\Source\\cwcontrol\\Custom\\DotNetRunner\\" wide
		$s7 = "ScreenConnect." ascii
		$s8 = "\\ScreenConnect.Core.pdb" ascii
		$s9 = "relay.screenconnect.com" ascii

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0xcfd0) and 3 of them
}
