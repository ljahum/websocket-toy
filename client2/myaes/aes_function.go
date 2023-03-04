package myaes

import (
	"bytes"
	"sync"
)

// blockSize is a block size(word units).
// keySize is a key size(word units).
const (
	keySize   = 4
	blockSize = 4
)

type DWORD uint32

var (
	//S-Box table. It provides confusion.
	_SBox = [16][16]byte{
		{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
		{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
		{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
		{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
		{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
		{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
		{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
		{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
		{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
		{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
		{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
		{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
		{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
		{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
		{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
		{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16},
	}
	//Inverse S-Box table. It's inverse function for S-Box.
	_invSBox = [16][16]byte{
		{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
		{0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
		{0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
		{0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
		{0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
		{0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
		{0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
		{0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
		{0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
		{0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
		{0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
		{0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
		{0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
		{0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
		{0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
		{0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d},
	}
	//Round constants
	rcon = [11]DWORD{
		0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
		0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000,
	}

	numberOfRound    = 0 // number of AES' round
	initializeVector []byte
	cipherText       []byte
	encNonce         []byte
	decNonce         []byte
	wg               *sync.WaitGroup //wait group
	//mu				 *sync.Mutex
)

func extractHighHEX(x byte) byte {
	return x >> 4
}

func extractLowHEX(x byte) byte {
	return x & 0x0F
}

// 循环左移
func rotWord(W DWORD) DWORD {
	W = ((W & 0xFF000000) >> 24) | (W << 8)
	return W
}

// 从32位字的MSB中各提取8位以应用S盒，并保存MSB中应用的值。
func subWord(W DWORD) DWORD {
	var out, mask DWORD = 0, 0xFF000000
	var shift byte = 24

	for i := 0; i < 4; i++ {
		//字节的前四位对应S-BOX行
		//底部四位对应Sbox列
		out += DWORD(_SBox[extractHighHEX(byte((W&mask)>>shift))][extractLowHEX(byte((W&mask)>>shift))]) << shift
		mask >>= 8
		shift -= 8
	}

	return out
}

// Convert byte to word.
func byteToDword(b0, b1, b2, b3 byte) DWORD {
	var temp = (DWORD(b0) << 24) | (DWORD(b1) << 16) | (DWORD(b2) << 8) | DWORD(b3)
	return temp
}

// Remove a "\r\n".
func trimSpace(in []byte) (int, []byte) {
	i := 0
	k := 0

	for in[i] != 0xD {
		i++
		k++
		if i > len(in)-1 {
			break
		}
	}
	if k != 0 {
		for i := k; i < len(in); i++ {
			in[i] = 0
		}
	}
	return k, in
}

// Key expansion of AES-128.
func keyExpansion(paramKey []byte, W []DWORD) {
	var temp DWORD
	var i int
	// 前四个bytes的操作
	for i = 0; i < keySize; i++ {
		W[i] = byteToDword(paramKey[4*i], paramKey[4*i+1], paramKey[4*i+2], paramKey[4*i+3])
	}
	//计算 个4 ~ 43个
	i = keySize
	for i < (blockSize * (numberOfRound + 1)) {
		temp = W[i-1]
		// 当 i mod 4 =0时
		// Wi-1 -> RotWord() -> SubWord() -> ^ RCON[i/4] -> ti
		if i%keySize == 0 {
			temp = subWord(rotWord(temp)) ^ rcon[i/keySize-1]
			W[i] = W[i-keySize] ^ temp
			i += 1
			// i mod 4 不为0时
			// Wi = Wi-1 ^ Wi-4
		} else {
			W[i] = W[i-1] ^ W[i-4]
			i += 1
		}
	}
}

// 循环异或
func addRoundKey(state [][]byte, roundKey []DWORD) {
	var mask, shift DWORD

	for i := 0; i < 4; i++ {
		shift = 24
		mask = 0xFF000000
		for j := 0; j < 4; j++ {
			state[j][i] = byte((roundKey[i]&mask)>>shift) ^ state[j][i]
			mask >>= 8
			shift -= 8
		}
	}
}

func subBytes(state [][]byte) {
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			//分别获取高8位喝低8位进行查表
			state[i][j] = _SBox[extractHighHEX(state[i][j])][extractLowHEX(state[i][j])]
		}
	}
}

func inverseSubBytes(state [][]byte) {
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			state[i][j] = _invSBox[extractHighHEX(state[i][j])][extractLowHEX(state[i][j])]
		}
	}
}

// 循环左移
func cirCleShiftRows(row []byte) {
	temp := row[0]
	row[0] = row[1]
	row[1] = row[2]
	row[2] = row[3]
	row[3] = temp
}

// 在加密过程中使用ShiftRows并向左移动 <-
// Row 0 : no shift
// Row 1 : 1 byte shift
// Row 2 : 2 byte shift
// Row 3 : 3 byte shift
func shiftRows(state [][]byte) {
	for i := 0; i < 4; i++ {
		for j := 0; j < i; j++ {
			cirCleShiftRows(state[i])
		}
	}
}

func inverseCircleShiftRows(row []byte) {
	temp := row[3]
	row[3] = row[2]
	row[2] = row[1]
	row[1] = row[0]
	row[0] = temp
}

// 在加密过程中使用inverseShiftRows并向右移动 ->
// Row 0 : no shift
// Row 1 : 1 byte shift
// Row 2 : 2 byte shift
// Row 3 : 3 byte shift
func inverseShiftRows(state [][]byte) {
	for i := 0; i < 4; i++ {
		for j := 0; j < i; j++ {
			inverseCircleShiftRows(state[i])
		}
	}
}

// Multiplication operation in GF(2^8)
func xTime(b, n byte) byte {
	//使用byte类型自动模上256
	var temp, mask byte = 0, 0x01

	for i := 0; i < 8; i++ {
		// 11
		//模仿模重复平方法的思想
		//对n的二进制每一位检查来决定每一位时的算法
		if (n & mask) != 0 {
			temp ^= b
		}

		//If x7=0, y=(x<<1)
		//If x7=1, y=(x<<1) ^ 0x1b
		//判断最高位是否有溢出
		if (b & 0x80) == 0x80 {
			b = (b << 1) ^ 0x1B
		} else {
			b <<= 1
		}
		mask <<= 1
	}
	return temp
}

func mixColumns(state [][]byte) {
	//特征矩阵
	a := [][]byte{
		{0x02, 0x03, 0x01, 0x01},
		{0x01, 0x02, 0x03, 0x01},
		{0x01, 0x01, 0x02, 0x03},
		{0x03, 0x01, 0x01, 0x02},
	}

	for i := 0; i < 4; i++ {
		temp := make([]byte, 4)
		for j := 0; j < 4; j++ {
			for k := 0; k < 4; k++ {
				//x乘
				temp[j] ^= xTime(state[k][i], a[j][k])
			}

		}
		state[0][i] = temp[0]
		state[1][i] = temp[1]
		state[2][i] = temp[2]
		state[3][i] = temp[3]
	}
}

func inverseMixColumns(state [][]byte) {

	a := [][]byte{
		{0x0E, 0x0B, 0x0D, 0x09},
		{0x09, 0x0E, 0x0B, 0x0D},
		{0x0D, 0x09, 0x0E, 0x0B},
		{0x0B, 0x0D, 0x09, 0x0E},
	}

	for i := 0; i < 4; i++ {
		temp := make([]byte, 4)
		for j := 0; j < 4; j++ {
			for k := 0; k < 4; k++ {
				temp[j] ^= xTime(state[k][i], a[j][k])
			}
		}
		state[0][i] = temp[0]
		state[1][i] = temp[1]
		state[2][i] = temp[2]
		state[3][i] = temp[3]
	}
}

func EncryptAES(paramPlain []byte, paramCipher []byte, paramKey []byte) {
	state := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		state[i] = make([]byte, 4)
	}
	var W []DWORD
	numberOfRound = 10
	W = make([]DWORD, 32*blockSize*(numberOfRound+1))

	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			state[j][i] = paramPlain[i*4+j]
		}
	}
	//密钥扩展.
	keyExpansion(paramKey, W)
	//轮密钥加
	addRoundKey(state, W)

	//1到10轮的加密
	for i := 0; i < numberOfRound-1; i++ {
		//字节替换
		subBytes(state)
		//行位移
		shiftRows(state)
		//列混淆
		mixColumns(state)
		addRoundKey(state, W[(i+1)*4:])
	}
	//round 11
	i := numberOfRound
	subBytes(state)
	shiftRows(state)
	addRoundKey(state, W[i*4:])

	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			paramCipher[i*4+j] = state[j][i]
		}
	}
}

func DecryptAES(paramCipher []byte, paramComplete []byte, paramKey []byte) {
	state := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		state[i] = make([]byte, 4)
	}
	var W []DWORD
	numberOfRound = 10
	W = make([]DWORD, 32*blockSize*(numberOfRound+1))

	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			state[j][i] = paramCipher[i*4+j]
		}
	}
	//密钥扩展.
	keyExpansion(paramKey, W)
	//轮密钥加
	addRoundKey(state, W[numberOfRound*blockSize:])

	for i := 0; i < numberOfRound-1; i++ {
		// 逆字节替换
		inverseShiftRows(state)
		// 逆行位移
		inverseSubBytes(state)
		addRoundKey(state, W[(numberOfRound-i-1)*blockSize:])
		// 逆列混淆
		inverseMixColumns(state)
	}

	i := numberOfRound
	inverseSubBytes(state)
	inverseShiftRows(state)
	addRoundKey(state, W[(numberOfRound-i)*blockSize:])

	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			paramComplete[i*4+j] = state[j][i]
		}
	}
}

func EncryptecbMode(paramPlainText []byte, paramKey []byte) []byte {
	plainText := make([]byte, 16)
	cipherText = make([]byte, 16)
	secretKey := make([]byte, 16)
	//var i = 0

	// 密文喝密钥的格式化
	copy(plainText, paramPlainText)
	_, plainText = trimSpace(plainText)
	copy(secretKey, paramKey)
	_, secretKey = trimSpace(secretKey)

	EncryptAES(plainText, cipherText, secretKey)
	return cipherText

}

func DecryptecbMode(cipher []byte, paramKey []byte) []byte {
	cipherText := make([]byte, 16)
	msg := make([]byte, 16)
	secretKey := make([]byte, 16)

	copy(cipherText, cipher)
	_, cipherText = trimSpace(cipherText)
	copy(secretKey, paramKey)
	_, secretKey = trimSpace(secretKey)

	DecryptAES(cipherText, msg, secretKey)
	return msg
}

func PKCS7Padding(ciphertext []byte, blockSize int) ([]byte, error) {
	//length := len(ciphertext)
	padding := blockSize - len(ciphertext)%blockSize //padding长度

	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...), nil
}

// PKCS7填充的反向操作，删除填充的字符串
func PKCS7UnPadding(origData []byte) ([]byte, error) {
	//获取数据长度
	length := len(origData)
	//获取填充字符串长度
	unpadding := int(origData[length-1])

	return origData[:(length - unpadding)], nil

}

func EncryptecbMode_withPadding(paramPlainText []byte, paramKey []byte) []byte {
	padded_plaintext, _ := PKCS7Padding(paramPlainText, 16)
	cipherText := []byte("")
	for i := 0; i < len(padded_plaintext)/16; i++ {
		cipherblock := EncryptecbMode(padded_plaintext[i*16:i*16+16], paramKey)
		cipherText = append(cipherText, cipherblock...)
	}
	return cipherText
}

func DecryptecbMode_withUnpadding(cipher []byte, paramKey []byte) []byte {

	plaintext := []byte("")
	for i := 0; i < len(cipher)/16; i++ {
		plaintextblock := DecryptecbMode(cipher[i*16:i*16+16], paramKey)
		plaintext = append(plaintext, plaintextblock...)
	}
	plaintext, _ = PKCS7UnPadding(plaintext)
	return plaintext
}
