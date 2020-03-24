rule glps {
	meta:
		description = "Sample is from urlhaus: https://urlhaus.abuse.ch/url/329292/"
		in_the_wild = true
		author = "backslash"
		date = "3/24/2020"
		md5_hash = "220c6a2faa4979c9ccbb9cb05aeaca6b"

	strings:
		$stringA = "MS-DEFN_TYPEBIND"
		$stringB = "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;BU)(A;;GRGX;;;AC)(A;;GRGX;;;S-1-15-2-2)"
		$stringC = "Read Server entry %ws in scope %!Windows::Foundation::RegistrationScope!, property ActivatableClasses : %!HRESULT!"
		$stringD = "SELF.EXE"
		$stringE = "Software\\Policies\\Microsoft\\Windows\\App Management"
        $deviceCamera = {68 AC 28 12 75 8D 4C 24 14 89 5C 24 24 66 89 44}


	condition:
		5 or more
        
}   



