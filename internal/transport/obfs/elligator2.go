package obfs

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const (
	fieldSize       = 392
	sqrtMinus1      = "8b5f48e430274585b63d139b8ad2d635"
	elligator2Field = 392
)

var (
	p, _             = new(big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
	pMinus1Div2, _   = new(big.Int).SetString("3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff76", 16)
	sqrtMinus1Int, _ = new(big.Int).SetString(sqrtMinus1, 16)
	one              = big.NewInt(1)
	two              = big.NewInt(2)
)

type Elligator2 struct{}

func NewElligator2() *Elligator2 {
	return &Elligator2{}
}

func (e *Elligator2) Encode(publicKey []byte) ([]byte, error) {
	if len(publicKey) != 32 {
		return nil, fmt.Errorf("invalid public key length: expected 32, got %d", len(publicKey))
	}

	u := new(big.Int).SetBytes(publicKey)
	u.Mod(u, p)

	if u.Cmp(pMinus1Div2) > 0 {
		u.Sub(p, u)
	}

	legendre := e.legendreSymbol(u)
	if legendre == 1 {
		u.Sub(p, u)
	}

	r, err := e.encodeMontgomery(u)
	if err != nil {
		return nil, err
	}

	result := make([]byte, 32)
	r.FillBytes(result)

	return result, nil
}

func (e *Elligator2) Decode(representative []byte) ([]byte, error) {
	if len(representative) != 32 {
		return nil, fmt.Errorf("invalid representative length: expected 32, got %d", len(representative))
	}

	r := new(big.Int).SetBytes(representative)
	r.Mod(r, p)

	u, err := e.decodeMontgomery(r)
	if err != nil {
		return nil, err
	}

	result := make([]byte, 32)
	u.FillBytes(result)

	return result, nil
}

func (e *Elligator2) encodeMontgomery(u *big.Int) (*big.Int, error) {
	oneMinusU := new(big.Int).Sub(p, u)
	oneMinusU.Sub(oneMinusU, one)
	oneMinusU.Mod(oneMinusU, p)

	onePlusU := new(big.Int).Add(u, one)
	onePlusU.Mod(onePlusU, p)

	denom := new(big.Int).Mul(oneMinusU, onePlusU)
	denom.Mod(denom, p)

	if denom.Sign() == 0 {
		denom.Set(one)
	}

	denomInv := new(big.Int).ModInverse(denom, p)
	if denomInv == nil {
		return nil, fmt.Errorf("no modular inverse")
	}

	v := new(big.Int).Mul(u, denomInv)
	v.Mod(v, p)

	vSq := new(big.Int).Mul(v, v)
	vSq.Mod(vSq, p)

	rSq := new(big.Int).Mul(vSq, sqrtMinus1Int)
	rSq.Mod(rSq, p)

	r := e.sqrt(rSq)
	if r == nil {
		return nil, fmt.Errorf("no square root")
	}

	return r, nil
}

func (e *Elligator2) decodeMontgomery(r *big.Int) (*big.Int, error) {
	rSq := new(big.Int).Mul(r, r)
	rSq.Mod(rSq, p)

	oneMinusRSq := new(big.Int).Sub(p, rSq)
	oneMinusRSq.Sub(oneMinusRSq, one)
	oneMinusRSq.Mod(oneMinusRSq, p)

	if oneMinusRSq.Sign() == 0 {
		return big.NewInt(0), nil
	}

	onePlusRSq := new(big.Int).Add(rSq, one)
	onePlusRSq.Mod(onePlusRSq, p)

	denom := new(big.Int).Mul(oneMinusRSq, onePlusRSq)
	denom.Mod(denom, p)

	if denom.Sign() == 0 {
		return big.NewInt(0), nil
	}

	denomInv := new(big.Int).ModInverse(denom, p)
	if denomInv == nil {
		return nil, fmt.Errorf("no modular inverse")
	}

	u := new(big.Int).Mul(rSq, denomInv)
	u.Mul(u, sqrtMinus1Int)
	u.Mod(u, p)

	return u, nil
}

func (e *Elligator2) sqrt(n *big.Int) *big.Int {
	exp := new(big.Int).Add(p, big.NewInt(3))
	exp.Div(exp, big.NewInt(8))

	result := new(big.Int).Exp(n, exp, p)

	check := new(big.Int).Mul(result, result)
	check.Mod(check, p)

	if check.Cmp(n) != 0 {
		result.Mul(result, sqrtMinus1Int)
		result.Mod(result, p)
	}

	check.Mul(result, result)
	check.Mod(check, p)

	if check.Cmp(n) != 0 {
		return nil
	}

	return result
}

func (e *Elligator2) legendreSymbol(n *big.Int) int {
	exp := new(big.Int).Sub(p, one)
	exp.Div(exp, two)

	result := new(big.Int).Exp(n, exp, p)

	switch result.Cmp(one) {
	case 0:
		return 1
	case -1:
		if result.Cmp(new(big.Int).Sub(p, one)) == 0 {
			return -1
		}
		return 0
	default:
		return 0
	}
}

func (e *Elligator2) GenerateObfuscatedPublicKey(originalPubKey []byte) ([]byte, error) {
	obfuscated, err := e.Encode(originalPubKey)
	if err != nil {
		return nil, err
	}

	randomSuffix := make([]byte, 8)
	rand.Read(randomSuffix)

	for i := 0; i < 8 && 24+i < len(obfuscated); i++ {
		obfuscated[24+i] ^= randomSuffix[i]
	}

	return obfuscated, nil
}

func (e *Elligator2) RecoverPublicKey(obfuscatedKey []byte) ([]byte, error) {
	if len(obfuscatedKey) != 32 {
		return nil, fmt.Errorf("invalid obfuscated key length")
	}

	keyCopy := make([]byte, 32)
	copy(keyCopy, obfuscatedKey)

	return e.Decode(keyCopy)
}

type NTorHandshake struct {
	elligator *Elligator2
}

func NewNTorHandshake() *NTorHandshake {
	return &NTorHandshake{
		elligator: NewElligator2(),
	}
}

type NTorHandshakeState struct {
	ClientPublic  []byte
	ClientPrivate []byte
	ServerPublic  []byte
	SessionKey    []byte
}

func (n *NTorHandshake) GenerateClientHandshake(nodeID, serverPubKey []byte) (*NTorHandshakeState, error) {
	clientPrivate := make([]byte, 32)
	rand.Read(clientPrivate)

	clientPublic := make([]byte, 32)
	rand.Read(clientPublic)

	obfuscatedPub, err := n.elligator.GenerateObfuscatedPublicKey(clientPublic)
	if err != nil {
		return nil, fmt.Errorf("obfuscate public key: %w", err)
	}

	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)

	return &NTorHandshakeState{
		ClientPublic:  obfuscatedPub,
		ClientPrivate: clientPrivate,
		ServerPublic:  serverPubKey,
		SessionKey:    sessionKey,
	}, nil
}

func (n *NTorHandshake) ProcessServerResponse(state *NTorHandshakeState, response []byte) error {
	if len(response) < 64 {
		return fmt.Errorf("response too short")
	}

	serverPublic := response[:32]
	authTag := response[32:64]

	_ = serverPublic
	_ = authTag

	return nil
}

func (n *NTorHandshake) CreateServerResponse(clientHandshake []byte, serverPrivate []byte) ([]byte, error) {
	serverPublic := make([]byte, 32)
	rand.Read(serverPublic)

	serverObfuscated, err := n.elligator.GenerateObfuscatedPublicKey(serverPublic)
	if err != nil {
		return nil, err
	}

	authTag := make([]byte, 32)
	rand.Read(authTag)

	response := make([]byte, 64)
	copy(response[:32], serverObfuscated)
	copy(response[32:], authTag)

	return response, nil
}
