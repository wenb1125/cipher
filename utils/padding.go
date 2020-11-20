package utils

import "bytes"

/**
 *为明文进行PCKS5加密尾部填充
 */
func PKCS5EndPadding(data []byte, blockSize int) []byte {
	//1.计算要填充多少个
	size := blockSize - len(data)%blockSize
	//2.准备要填充的内容
	paddingText := bytes.Repeat([]byte{byte(size)},size)
	//3.填充
	return append(data,paddingText...)
}


/**
 * 去除尾部填充的数据内容，返回元数据
 */
func ClearPKCS5Padding(data []byte, blockSize int) []byte {
	clearSize := int(data[len(data)-1])
	return data[:len(data)-clearSize]
}

/**
 *为明文进行Zeros加密尾部填充
 */
func ZeroEndPadding(data []byte, blockSize int) []byte {
	//1.计算要填充多少个
	size := blockSize - len(data)%blockSize
	//2.准备要填充的内容
	paddingText := bytes.Repeat([]byte{byte(0)},size)
	//3.填充
	return append(data,paddingText...)
}


/**
 * 将Zeros尾部填充的数据去除
 */
func ClearZerosPadding(data []byte, blockSize int) []byte {
	size := blockSize - len(data)%blockSize
	return data[:len(data)-size]
}

