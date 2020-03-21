rule cirilic{
	meta:
		description = "Thank you again urlhaus for this sample: https://urlhaus.abuse.ch/url/327775/"
		in_the_wild = true
		author = "backslash"
		date = "3/20/2020"
		md5_hash ="f6f130bacb418e4c30414ec838a688ad"
	strings:
		$a = "tcpip-platform-libraries-mw-license-RtcMobileCore"
		$b = "_____________________________________________"
		$c = "S-1-15-3-1024-1502825166-1963708345-2616377461-2562897074-4192028372-3968301570-1997628692-1435953622"
		$d = {777DA32B  9A AC 01 04 15 BA 0E B0 6F F4 F7 E1 EB 62 D6 2B}
	condition:
		4 of them
}
