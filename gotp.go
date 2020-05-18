package gotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"strconv"
	"strings"
	"time"
)

type OTP struct {
	Digit    int
	TimeStep int64
	BaseTime int64
	Hash     func() hash.Hash
	Secret   []byte
}

func (this *OTP) HOTP(count uint64) uint {
	key := make([]byte, base32.StdEncoding.DecodedLen(len(this.Secret)))
	base32.StdEncoding.Decode(key, this.Secret)
	hm := hmac.New(this.Hash, key)
	binary.Write(hm, binary.BigEndian, count)
	hs := hm.Sum(nil)
	offset := int(hs[len(hs)-1] & 0xF)
	sbits := hs[offset : offset+4]
	sbits[0] &= 0x7F
	snum := uint(sbits[3]) | uint(sbits[2])<<8
	snum |= uint(sbits[1])<<16 | uint(sbits[0])<<24
	return snum % uint(math.Pow(10, float64(this.Digit)))
}

func (this *OTP) TOTP(timestamp int64) uint {
	count := uint64(math.Floor(float64(timestamp-this.BaseTime) / float64(this.TimeStep)))
	return this.HOTP(count)
}

func (this *OTP) formatString(otp uint) string {
	return fmt.Sprintf("%0"+strconv.Itoa(this.Digit)+"d", otp)
}

func (this *OTP) GenerateByCount(count uint64) string {
	return this.formatString(this.HOTP(count))
}

func (this *OTP) GenerateByTime() string {
	return this.formatString(this.TOTP(time.Now().Unix()))
}

func NewGoogleAuth(secret string) (*OTP, error) {
	if n := len(secret) % 8; n > 0 {
		secret += strings.Repeat("=", 8-n)
	}
	b, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, err
	}
	return &OTP{
		Digit:    6,
		TimeStep: 30,
		BaseTime: 0,
		Hash:     sha1.New,
		Secret:   b,
	}, nil
}

func GenerateSecret(key []byte) string {
	return strings.TrimRight(base32.StdEncoding.EncodeToString(key), "=")
}
