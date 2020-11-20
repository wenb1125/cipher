package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"hash/utils"
	"os"
)

const RSA_PRIVATE_KEY = "RSA PRIVATE KEY"
const RSA_PUBVATE_KEY = "RSA PUBLIC KEY"


//该函数用于生成一对RSA密钥对,并返回密钥数据
func CreateRSAKey() (*rsa.PrivateKey, error) {
	var bits int
	flag.IntVar(&bits, "b", 2048, "rsa密钥的长度")
	//1.私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	//将私钥进行返回
	return privateKey, nil
}

//生成一对密钥,并以pem文件格式进行保存,即生成两个证书文件
func GenerateKeysPem(file_name string) error {
	//1.先生成私钥
	pri, err := CreateRSAKey()
	if err != nil {
		return err
	}
	//2.生成私钥证书
	err = generatePriPem(pri, file_name)
	if err != nil {
		return err
	}
	//3.生成公钥证书
	err = generatePubPem(pri.PublicKey, file_name)
	if err != nil {
		return err
	}
	return nil
}

//保存私钥公钥数据到文件中,进行持久化存储
//用于根据私钥生成一个私钥证书文件
func generatePriPem(pri *rsa.PrivateKey, file_name string) error {
	//1.对私钥进行序列化
	priBytes := x509.MarshalPKCS1PrivateKey(pri)
	//2.新建文件
	file, err := os.Create("rsa_pri_" + file_name + ".pem")
	if err != nil {
		return err
	}
	//3.block
	block := pem.Block{
		Type: RSA_PRIVATE_KEY,
		Bytes: priBytes,
	}
	//4.写入
	return pem.Encode(file, &block)
}

//生成一个公钥证书文件
func generatePubPem(pub rsa.PublicKey, file_name string) error {
	pubBytes := x509.MarshalPKCS1PublicKey(&pub)
	file, err := os.Create("rsa_pub_" +file_name + ".pem")
	if err != nil {
		return err
	}
	block := pem.Block{
		Type: RSA_PUBVATE_KEY,
		Bytes: pubBytes,
	}
	return pem.Encode(file, &block)
}

//第一种:公钥加密,私钥解密
//使用RSA算法对数据data进行加密,并返回加密后的密文
func RSAEncrypt(pub rsa.PublicKey, data []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, &pub, data)
}
//使用RSA算法对密文数据进行解密,返回解密后的明文
func RSADecrypt(pri *rsa.PrivateKey, cipher []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, pri, cipher)
}

//第二种:私钥签名,公钥验签
//使用rsa算法对数据进行签名
func RSASign(pri *rsa.PrivateKey, data []byte) ([]byte, error) {
	hashed := utils.MD5Hash(data)
	return rsa.SignPKCS1v15(rand.Reader, pri, crypto.MD5, hashed)
}
//使用rsa算法进行签名验证
func RSAVerify(pub rsa.PublicKey, data []byte, sign []byte) (bool, error) {
	hashed := utils.MD5Hash(data)
	verifyResult := rsa.VerifyPKCS1v15(&pub, crypto.MD5, hashed, sign)
	return verifyResult == nil, verifyResult
}
