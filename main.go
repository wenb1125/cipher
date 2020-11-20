package main

import (
	"fmt"
	_des "hash/3des"
	"hash/aes"
	"hash/des"
	"hash/rsa"
)

func main() {
	key := []byte("20201112") //des秘钥长度：8
	data := "穷在闹市无人问，富在深山有远亲"

	//1、加密
	cipherText, err := des.DESEnCrypt([]byte(data), key)
	if err != nil {
		fmt.Println("加密失败：", err.Error())
		return
	}
	//2、解密
	originalText, err := des.DESDeCrypt(cipherText, key)
	if err != nil {
		fmt.Println("解密失败：", err.Error())
		return
	}
	fmt.Println("DES解密结果：", string(originalText))

	//二、3DES算法
	key1 := []byte("202011122020111220201112") //3des密钥长度必须为24字节
	data1 := "窗含西岭千秋雪，门泊东吴万里船"

	cipherText1, err := _des.TripleDesEncrypt([]byte(data1), key1)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	originalText1, err := _des.TripleDesDecrypt(cipherText1, key1)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("3DES算法解密后的内容：", string(originalText1))

	//3、AES算法
	//AES算法密钥长度：16字节、24字节、32字节
	//16->128位  24->192位  32->256位
	key2 := []byte("20201112202011122020111220201112") //8

	data2 := "只是因为在人群中多看了你一眼，再也没能忘记你容颜"
	cipherText2, err := aes.AESEncrypt([]byte(data2), key2)
	if err != nil {
		//crypto/aes: invalid key size 8
		fmt.Println(err.Error())
		return
	}
	fmt.Println("AES算法加密后的内容:", string(cipherText2))

	//4、RSA算法
	fmt.Println("=================RSA算法======================")

	//4.1.5 将私钥保存到文件中
	err = rsa.GenerateKeysPem("dw")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
}
