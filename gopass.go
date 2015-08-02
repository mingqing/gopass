package gopass

import (
	"crypto/md5"
	"crypto/rand"
	"errors"
	"strings"
)

var (
	errNotSupport        = errors.New("not support")
	errPasswordTooLength = errors.New("password too length")
	errHashPassFail      = errors.New("hash password fail")
	errHashDataTooSmall  = errors.New("hash data is too small")
	errInvalidHashData   = errors.New("invalid hash data")
	errInternalFail      = errors.New("internal error")
)

type passwordHash struct {
	itoa64             string
	portableHashes     bool
	iterationCountLog2 int
}

func NewPasswordHash(iterationCountLog2 int, portableHashes bool) *passwordHash {
	itoa64 := "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

	if iterationCountLog2 < 4 || iterationCountLog2 > 31 {
		iterationCountLog2 = 8
	}

	return &passwordHash{
		itoa64:             itoa64,
		iterationCountLog2: iterationCountLog2,
		portableHashes:     portableHashes}
}

func (this *passwordHash) HashPassword(password string) (string, error) {
	if len(password) > 4096 {
		return "*", errPasswordTooLength
	}

	if this.portableHashes {
		input, err := this.getRandomBytes(6)
		if err != nil {
			return "*", err
		}

		hash, _ := this.cryptPrivate(password, this.gensaltPrivate(input))
		if len(hash) == 34 {
			return hash, nil
		}
	} else {
		/*
			input, _ := this.getRandomBytes(16)
			input = []byte("limiqi1111111111")
			t := this.gensaltBlowfish(input)
			return string(t), nil
		*/
		return "*", errNotSupport
	}

	return "*", errHashPassFail
}

func (this *passwordHash) CheckPassword(password, storedHash string) bool {
	if len(password) > 4096 {
		return false
	}

	hash, _ := this.cryptPrivate(password, storedHash)
	if string(hash[0]) == "*" {
		// not implement
	}

	return hash == storedHash
}

func (this *passwordHash) getRandomBytes(length int) ([]byte, error) {
	output := make([]byte, length)

	if _, err := rand.Read(output); err != nil {
		return nil, err
	}

	return output, nil
}

func (this *passwordHash) gensaltPrivate(input []byte) string {
	output := []byte("$P$")
	if this.iterationCountLog2 > 30 {
		output = append(output, this.itoa64[30])
	} else {
		output = append(output, this.itoa64[this.iterationCountLog2+5])
	}

	output = append(output, this.encode64(input, 6)...)

	return string(output)
}
func (this *passwordHash) gensaltBlowfish(input []byte) string {
	this.itoa64 = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

	output := []byte("$2a$")
	output = append(output, byte('0'+this.iterationCountLog2/10))
	output = append(output, byte('0'+this.iterationCountLog2%10))
	output = append(output, byte('$'))

	var i int = 0
	for {
		c1 := int(input[i])
		i++

		output = append(output, this.itoa64[c1>>2])
		c1 = (c1 & 0x03) << 4
		if i >= 16 {
			output = append(output, this.itoa64[c1])
			break
		}

		c2 := int(input[i])
		i++

		c1 |= c2 >> 4
		output = append(output, this.itoa64[c1])
		c1 = (c2 & 0x0f) << 2

		c2 = int(input[i])
		i++

		c1 |= c2 >> 6
		output = append(output, this.itoa64[c1])
		output = append(output, this.itoa64[c2&0x3f])
	}

	return string(output)
}
func (this *passwordHash) gensaltExtended(input []byte) string {
	countLog2 := this.iterationCountLog2 + 8
	if countLog2 > 24 {
		countLog2 = 24
	}

	var count uint = (1 << uint(countLog2)) - 1

	output := []byte("_")
	output = append(output, this.itoa64[(count&0x3f)])
	output = append(output, this.itoa64[(count>>6)&0x3f])
	output = append(output, this.itoa64[(count>>12)&0x3f])
	output = append(output, this.itoa64[(count>>18)&0x3f])
	output = append(output, this.encode64(input, 3)...)

	return string(output)
}

func (this *passwordHash) cryptPrivate(password, setting string) (string, error) {
	output := "*0"

	if len(setting) < 12 {
		return output, errHashDataTooSmall
	}

	// will be '$P$'
	id := setting[:3]
	if id != "$P$" && id != "$H$" {
		return output, errInvalidHashData
	}

	// most possible eq 13
	countLog2 := strings.Index(this.itoa64, setting[3:4])
	if countLog2 < 7 || countLog2 > 30 {
		return output, errInternalFail
	}

	var count uint = 1 << uint(countLog2)
	salt := setting[4:12]
	if len(salt) != 8 {
		return output, errInternalFail
	}

	rawData := append([]byte(salt), []byte(password)...)
	hashData := md5.Sum(rawData)

	for i := 0; i < int(count); i++ {
		rawData = append(hashData[:], []byte(password)...)
		hashData = md5.Sum(rawData)
	}

	output = setting[:12]
	output += string(this.encode64(hashData[:], 16))

	return output, nil
}

func (this *passwordHash) encode64(input []byte, count int) []byte {
	i := 0
	output := []byte{}

	for {
		value := int(input[i])
		i++

		output = append(output, this.itoa64[(value&0x3f)])

		if i < count {
			value = value | int(input[i])<<8
		}

		output = append(output, this.itoa64[((value>>6)&0x3f)])

		if i >= count {
			break
		}
		i++

		if i < count {
			value = value | int(input[i])<<16
		}
		output = append(output, this.itoa64[((value>>12)&0x3f)])

		if i >= count {
			break
		}
		i++

		output = append(output, this.itoa64[((value>>18)&0x3f)])

		if i >= count {
			break
		}
	}

	return output
}
