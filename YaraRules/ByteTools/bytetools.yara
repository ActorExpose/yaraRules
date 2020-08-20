rule ByteTools {
	meta:
		description = "Thanks to virus share for this sample"
		in_the_wild = true
		author = "backslash"
		data = "8/20/2020"
		md5_hash = "b4e83eefb3f258a77bb74b97571176b5"
	
	strings:
		$a = "StealerBin.exe"
		$b = "StealerBin"
		$c = "System.Net.Http"
	
	condition:
		2 of them
}