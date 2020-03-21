rule Coronovir{

	meta:
		description = "Thanks to urlhaus for this sample: http://oronsuuts.com/upload/coronovir.exe"
		in_the_wild = true
		author = "backslash"
		date = "3/20/2020"
		md5_hash = "de322e3441d3d8bccd8434218ffdd6f3"

	strings:
		$u = "DT~CYYLO8~OrrR8#?~13WpdCWYn3c*}3N2o7R2"
		$u2 = "brainpoolP160r1
		$u3 = "AddCredentials API"
		$u4 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/RtlSubscribeWnfStateChangeNotification
		$u5 = ":Jan:January:Feb:February:Mar:March:Apr:April:May:May:Jun:June:Jul:July:Aug:August:Sep:September:Oct:October:Nov:November:Dec:December"
		$ps = {50 72 6F 78 79 53 74 75 62 43 6C 73 69 64 33 32}



	condition:
		4 of them

}
