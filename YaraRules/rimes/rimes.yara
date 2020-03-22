rule rimes {
	meta:
		description = "Thanks to urlhaus for this sample: https://urlhaus.abuse.ch/url/327288/"
		in_the_wild = true
		author = "backslash"
		date = "3/21/2020"
		md5_hash = "3c4eff0348c24494cb11e0437da4ff32"

	strings:
		$reg = "Software\\Microsoft\\SystemCertificates\\Root\\ProtectedRoots"
        $uniquet = {81 00 00 1E 80 00 00 07 82 00 00 00 00 00 00 1F}
        $call = "rimes.exe"


	condition:
       $stringA and $reg and $unique
}   



