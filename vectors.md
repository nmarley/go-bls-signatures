## Test vectors

### Signatures
* keygen([1,2,3,4,5])
    * sk1: 0x022fb42c08c12de3a6af053880199806532e79515f94e83461612101f9412f9e
    * pk1 fingerprint: 0x26d53247
* keygen([1,2,3,4,5,6])
    * pk2 fingerprint: 0x289bb56e
* sign([7,8,9], sk1)
    * sig1:  0x93eb2e1cb5efcfb31f2c08b235e8203a67265bc6a13d9f0ab77727293b74a357ff0459ac210dc851fcb8a60cb7d393a419915cfcf83908ddbeac32039aaa3e8fea82efcb3ba4f740f20c76df5e97109b57370ae32d9b70d256a98942e5806065
* sign([7,8,9], sk2)
    * sig2: 0x975b5daa64b915be19b5ac6d47bc1c2fc832d2fb8ca3e95c4805d8216f95cf2bdbb36cc23645f52040e381550727db420b523b57d494959e0e8c0c6060c46cf173872897f14d43b2ac2aec52fc7b46c02c5699ff7a10beba24d3ced4e89c821e
* verify(sig1, AggregationInfo(pk1, [7,8,9]))
    * true
* verify(sig2, AggregationInfo(pk2, [7,8,9]))
    * true

### Aggregation
* aggregate([sig1, sig2])
    * aggSig: 0x975b5daa64b915be19b5ac6d47bc1c2fc832d2fb8ca3e95c4805d8216f95cf2bdbb36cc23645f52040e381550727db420b523b57d494959e0e8c0c6060c46cf173872897f14d43b2ac2aec52fc7b46c02c5699ff7a10beba24d3ced4e89c821e
* verify(aggSig2, mergeInfos(sig1.aggInfo, sig2.aggInfo))
    * true
* verify(sig1, AggregationInfo(pk2, [7,8,9]))
    * false
* sig3 = sign([1,2,3], sk1)
* sig4 = sign([1,2,3,4], sk1)
* sig5 = sign([1,2], sk2)
* aggregate([sig3, sig4, sig5])
    * aggSig2: 0x8b11daf73cd05f2fe27809b74a7b4c65b1bb79cc1066bdf839d96b97e073c1a635d2ec048e0801b4a208118fdbbb63a516bab8755cc8d850862eeaa099540cd83621ff9db97b4ada857ef54c50715486217bd2ecb4517e05ab49380c041e159b
* verify(aggSig2, mergeInfos(sig3.aggInfo, sig4.aggInfo, sig5.aggInfo))
    * true
* sig1 = sk1.sign([1,2,3,40])
* sig2 = sk2.sign([5,6,70,201])
* sig3 = sk2.sign([1,2,3,40])
* sig4 = sk1.sign([9,10,11,12,13])
* sig5 = sk1.sign([1,2,3,40])
* sig6 = sk1.sign([15,63,244,92,0,1])
* sigL = aggregate([sig1, sig2])
* sigR = aggregate([sig3, sig4, sig5])
* verify(sigL)
    * true
* verify(sigR)
    * true
* aggregate([sigL, sigR, sig6])
    * sigFinal: 0x07969958fbf82e65bd13ba0749990764cac81cf10d923af9fdd2723f1e3910c3fdb874a67f9d511bb7e4920f8c01232b12e2fb5e64a7c2d177a475dab5c3729ca1f580301ccdef809c57a8846890265d195b694fa414a2a3aa55c32837fddd80
* verify(sigFinal)
    * true

### Signature division
* divide(sigFinal, [sig2, sig5, sig6])
    * quotient: 0x8ebc8a73a2291e689ce51769ff87e517be6089fd0627b2ce3cd2f0ee1ce134b39c4da40928954175014e9bbe623d845d0bdba8bfd2a85af9507ddf145579480132b676f027381314d983a63842fcc7bf5c8c088461e3ebb04dcf86b431d6238f
* verify(quotient)
    * true
* divide(quotient, [sig6])
    * throws due to not subset
* divide(sigFinal, [sig1])
    * does not throw
* divide(sig_final, [sigL])
    * throws due to not unique
* sig7 = sign([9,10,11,12,13], sk2)
* sig8 = sign([15,63,244,92,0,1], sk2)
* sigFinal2 = aggregate([sigFinal, aggregate([sig7, sig8])])
* divide(sigFinal2, aggregate([sig7, sig8]))
    * quotient2: 0x06af6930bd06838f2e4b00b62911fb290245cce503ccf5bfc2901459897731dd08fc4c56dbde75a11677ccfbfa61ab8b14735fddc66a02b7aeebb54ab9a41488f89f641d83d4515c4dd20dfcf28cbbccb1472c327f0780be3a90c005c58a47d3
* verify(quotient2)
    * true

### HD keys
* esk = ExtendedPrivateKey([1, 50, 6, 244, 24, 199, 1, 25])
* esk.publicKeyFigerprint
    * 0xa4700b27
* esk.chainCode
    * 0xd8b12555b4cc5578951e4a7c80031e22019cc0dce168b3ed88115311b8feb1e3
* esk77 = esk.privateChild(77 + 2^31)
* esk77.publicKeyFingerprint
    * 0xa8063dcf
* esk77.chainCode
    * 0xf2c8e4269bb3e54f8179a5c6976d92ca14c3260dd729981e9d15f53049fd698b
* esk.privateChild(3).privateChild(17).publicKeyFingerprint
    * 0xff26a31f
* esk.extendedPublicKey.publicChild(3).publicChild(17).publicKeyFingerprint
    * 0xff26a31f
