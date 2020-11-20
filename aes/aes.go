package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"hash/utils"
)

/**
 *使用aes算法对数据进行加密
 */
func AESEncrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//明文数据尾部填充
	originData := utils.PKCS5EndPadding(data, block.BlockSize())
	mode := cipher.NewCBCEncrypter(block,key[:block.BlockSize()])
	cipherText := make([]byte,len(originData))
	mode.CryptBlocks(cipherText, originData)
	return cipherText, nil
}

func AESDecrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, key[:block.BlockSize()])
	originalText := make([]byte, len(data))
	mode.CryptBlocks(originalText,data)
	//去除尾部填充
	originalText = utils.ClearPKCS5Padding(originalText, block.BlockSize())
	return originalText, nil
}
