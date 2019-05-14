package bls

import (
	"encoding/binary"
	"math/big"
)

// ExtendedSecretKey represents a BLS extended private key.
type ExtendedSecretKey struct {
	Version           uint32
	Depth             uint8
	ParentFingerprint uint32
	ChildNumber       uint32
	SecretKey         *SecretKey
	ChainCode         *big.Int
}

// TODO ...
const (
	ExtendedSecretKeyVersion = 1
	ExtendedSecretKeySize    = 77
)

// SecretKeyFromSeed generates a private key from a seed, similar to HD key
// generation (hashes the seed), and reduces it mod the group order.
func ExtendedSecretKeyFromSeed(seed []byte) *ExtendedSecretKey {
	// TODO: Comment me later
	hmacKey := []byte("BLS HD seed")

	// TODO: Comment me later
	iLeft := Hmac256(append(seed, []byte{0}...), hmacKey)
	iRight := Hmac256(append(seed, []byte{1}...), hmacKey)

	// TODO: Comment me later
	skInt := new(big.Int).SetBytes(iLeft)
	skInt = new(big.Int).Mod(skInt, RFieldModulus)

	// it appears this is not needed b/c the byte slice is not used internally
	//// TODO: Comment me later
	////buf := [SecretKeySize]byte{}
	//
	//// TODO: Comment me later
	////skBytes := skInt.Bytes()
	//
	//// TODO: Comment me later
	////copy(buf[SecretKeySize-len(skBytes):], skBytes)

	// TODO: Comment me later
	sk := DeserializeSecretKey(skInt.Bytes())

	return &ExtendedSecretKey{
		Version:           ExtendedSecretKeyVersion,
		Depth:             0,
		ParentFingerprint: 0,
		ChildNumber:       0,
		ChainCode:         new(big.Int).SetBytes(iRight),
		SecretKey:         sk,
	}
}

// GetPublicKey ...
func (k *ExtendedSecretKey) GetPublicKey() *PublicKey {
	return k.SecretKey.PublicKey()
}

// GetChainCode ...
func (k *ExtendedSecretKey) GetChainCode() *big.Int {
	return k.ChainCode
}

// PrivateChild derives a child extEnded private key, hardened if i >= 2^31
func (k *ExtendedSecretKey) PrivateChild(i uint32) *ExtendedSecretKey {
	// NOTE: depth is a uint8 ...
	if k.Depth >= 255 {
		// throw std::string("Cannot go further than 255 levels");
		// TODO/NGM: Remove panic / return err
		panic("Cannot go further than 255 levels")
	}

	// Hardened keys have i >= 2^31. Non-hardened have i < 2^31
	hardened := i >= (1 << 31)

	var hmacInput []byte
	if hardened {
		hmacInput = k.SecretKey.Serialize()
	} else {
		hmacInput = k.GetPublicKey().Serialize()
	}

	// Now append i as 4 bytes to hmacInput (big endian)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], i)
	hmacInput = append(hmacInput, b[:]...)
	//fmt.Printf("NGMgo(PrivateChild) hmacInput: %x\n", hmacInput)

	cc := [32]byte{}
	ccBytes := k.ChainCode.Bytes()
	copy(cc[32-len(ccBytes):], ccBytes)

	iLeft := Hmac256(append(hmacInput, []byte{0}...), cc[:])
	iRight := Hmac256(append(hmacInput, []byte{1}...), cc[:])

	skInt := new(big.Int).SetBytes(iLeft)
	skInt.Add(skInt, k.SecretKey.f.n)
	skInt.Mod(skInt, RFieldModulus)
	sk := DeserializeSecretKey(skInt.Bytes())

	return &ExtendedSecretKey{
		Version:           ExtendedSecretKeyVersion,
		Depth:             k.Depth + 1,
		ParentFingerprint: k.GetPublicKey().Fingerprint(),
		ChildNumber:       i,
		ChainCode:         new(big.Int).SetBytes(iRight),
		SecretKey:         sk,
	}
}

// PublicChild derives a child extended public key, hardened if i >= 2^31
func (k *ExtendedSecretKey) PublicChild(i uint32) *ExtendedPublicKey {
	return k.PrivateChild(i).GetExtendedPublicKey()
}

// GetExtendedPublicKey ...
func (k *ExtendedSecretKey) GetExtendedPublicKey() *ExtendedPublicKey {
	buf := [ExtendedPublicKeySize]byte{}

	binary.BigEndian.PutUint32(buf[0:4], k.Version)
	buf[4] = k.Depth
	binary.BigEndian.PutUint32(buf[5:9], k.ParentFingerprint)
	binary.BigEndian.PutUint32(buf[9:13], k.ChildNumber)

	binary.BigEndian.PutUint32(buf[9:13], k.ChildNumber)

	ccBuf := [32]byte{}
	ccBytes := k.ChainCode.Bytes()
	copy(ccBuf[32-len(ccBytes):], ccBytes)

	// copy ChainCode bytes into buffer
	copy(buf[13:45], ccBuf[:])

	pkBytes := k.SecretKey.PublicKey().Serialize()
	copy(buf[45:], pkBytes)

	return ExtendedPublicKeyFromBytes(buf[:])
}

//// Parse public key and chain code from bytes
//static ExtendedPublicKey FromBytes(const uint8_t* serialized);
//
//// Derive a child extended public key, cannot be hardened
//ExtendedPublicKey PublicChild(uint32_t i) const;
//
//uint32_t GetVersion() const;
//uint8_t GetDepth() const;

// TODO ...
const (
	ExtendedPublicKeyVersion = 1
	ExtendedPublicKeySize    = 93
)

// ExtendedPublicKey represents a BLS extended public key.
type ExtendedPublicKey struct {
	Version           uint32
	Depth             uint8
	ParentFingerprint uint32
	ChildNumber       uint32
	ChainCode         *big.Int
	PublicKey         *PublicKey
}

// ExtendedPublicKeyFromBytes parses public key and chain code from bytes
func ExtendedPublicKeyFromBytes(b []byte) *ExtendedPublicKey {
	version := binary.BigEndian.Uint32(b[0:4])
	depth := uint8(b[4])
	parentFingerprint := binary.BigEndian.Uint32(b[5:9])
	childNumber := binary.BigEndian.Uint32(b[9:13])
	chainCode := new(big.Int).SetBytes(b[13:45])
	// TODO: check error?
	publicKey, _ := DeserializePublicKey(b[45:])

	return &ExtendedPublicKey{
		Version:           version,
		Depth:             depth,
		ParentFingerprint: parentFingerprint,
		ChildNumber:       childNumber,
		ChainCode:         chainCode,
		PublicKey:         publicKey,
	}
}

// PublicChild derives a child extended public key, cannot be hardened
func (k *ExtendedPublicKey) PublicChild(i uint32) *ExtendedPublicKey {
	// NOTE: depth is a uint8 ...
	if k.Depth >= 255 {
		// TODO/NGM: Remove panic / return err
		panic("Cannot go further than 255 levels")
	}

	// Hardened children have i >= 2^31. Non-hardened have i < 2^31
	if i >= (1 << 31) {
		// TODO/NGM: Remove panic / return err
		panic("Cannot derive hardened children from public key")
	}

	var hmacInput [PublicKeySize + 4]byte
	pkBytes := k.PublicKey.Serialize()
	copy(hmacInput[:], pkBytes)

	binary.BigEndian.PutUint32(hmacInput[PublicKeySize:], i)

	// Chain code is used as hmac key
	cc := [32]byte{}
	ccBytes := k.ChainCode.Bytes()
	copy(cc[32-len(ccBytes):], ccBytes)

	iLeft := Hmac256(append(hmacInput[:], []byte{0}...), cc[:])
	iRight := Hmac256(append(hmacInput[:], []byte{1}...), cc[:])

	skLeftInt := new(big.Int).SetBytes(iLeft)
	skLeftInt.Mod(skLeftInt, RFieldModulus)

	skLeft := DeserializeSecretKey(skLeftInt.Bytes())

	newG1 := skLeft.PublicKey().p.Add(k.PublicKey.p)
	newPk := &PublicKey{p: newG1}

	return &ExtendedPublicKey{
		Version:           k.Version,
		Depth:             k.Depth + 1,
		ParentFingerprint: k.PublicKey.Fingerprint(),
		ChildNumber:       i,
		ChainCode:         new(big.Int).SetBytes(iRight),
		PublicKey:         newPk,
	}
}
