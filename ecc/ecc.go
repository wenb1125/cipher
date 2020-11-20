package ecc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

//椭圆曲线数字签名算法私钥生成
func GenerateKey() (*ecdsa.PrivateKey, error) {
	//p256规则生成的一条曲线, p256Curve是一个结构体
	curve := elliptic.P256()
	return ecdsa.GenerateKey(curve, rand.Reader)
}

//私钥签名
func ECDSASign(pri ecdsa.PrivateKey, data []byte)  {

}

//公钥验签
func EXDSAVerify(pub ecdsa.PublicKey, data []byte)  {

}
