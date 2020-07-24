# sm-crypto

国密算法sm2、sm3和sm4的js版。


## 安装

```bash
npm install --save @salaku/sm-crypto
```

## sm2

### 获取密钥对

```js
const sm2 = require('@salaku/sm-crypto').sm2;

let keypair = sm2.generateKeyPairHex();

publicKey = keypair.publicKey; // 公钥
privateKey = keypair.privateKey; // 私钥
```

### 加密解密

```js
const sm2 = require('@salaku/sm-crypto').sm2;
const cipherMode = 1; // 1 - C1C3C2，0 - C1C2C3，默认为1

let encryptData = sm2.doEncrypt(msgString, publicKey, cipherMode); // 加密结果
let decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode); // 解密结果
```

### 签名验签

> ps：理论上来说，只做纯签名是最快的。

```js
const sm2 = require('@salaku/sm-crypto').sm2;

// 纯签名 + 生成椭圆曲线点
let sigValueHex = sm2.doSignature(msg, privateKey); // 签名
let verifyResult = sm2.doVerifySignature(msg, sigValueHex, publicKey); // 验签结果

// 纯签名
let sigValueHex2 = sm2.doSignature(msg, privateKey, {
    pointPool: [sm2.getPoint(), sm2.getPoint(), sm2.getPoint(), sm2.getPoint()], // 传入事先已生成好的椭圆曲线点，可加快签名速度
}); // 签名
let verifyResult2 = sm2.doVerifySignature(msg, sigValueHex2, publicKey); // 验签结果

// 纯签名 + 生成椭圆曲线点 + der编解码
let sigValueHex3 = sm2.doSignature(msg, privateKey, {
    der: true,
}); // 签名
let verifyResult3 = sm2.doVerifySignature(msg, sigValueHex3, publicKey, {
    der: true,
}); // 验签结果

// 纯签名 + 生成椭圆曲线点 + sm3杂凑
let sigValueHex4 = sm2.doSignature(msg, privateKey, {
    hash: true,
}); // 签名
let verifyResult4 = sm2.doVerifySignature(msg, sigValueHex4, publicKey, {
    hash: true,
}); // 验签结果

// 纯签名 + 生成椭圆曲线点 + sm3杂凑（不做公钥推导）
let sigValueHex5 = sm2.doSignature(msg, privateKey, {
    hash: true,
    publicKey, // 传入公钥的话，可以去掉sm3杂凑中推导公钥的过程，速度会比纯签名 + 生成椭圆曲线点 + sm3杂凑快
});
let verifyResult5 = sm2.doVerifySignature(msg, sigValueHex5, publicKey, {
    hash: true,
    publicKey,
});
```

### 获取椭圆曲线点

```js
const sm2 = require('@salaku/sm-crypto').sm2;

let poin = sm2.getPoint(); // 获取一个椭圆曲线点，可在sm2签名时传入
```

### 公钥压缩

```js
const sm2 = require('@salaku/sm-crypto').sm2;
let sk = 'f00df601a78147ffe0b84de1dffbebed2a6ea965becd5d0bd7faf54f1f29c6b5'

let beforeCompress = sm2.getPKFromSK(sk); // 从私钥生成未压缩的公钥
let compressed = sm2.compress(beforeCompress); // 压缩
```

### 公钥解压缩

```js
const sm2 = require('@salaku/sm-crypto').sm2;

let deCompressed = sm2.deCompress('02b507fe1afd0cc7a525488292beadbe9f143784de44f8bc1c991636509fd50936')
```

### 带 userid 的签名

```js
const sm2 = require('@salaku/sm-crypto').sm2;
let sk = 'f00df601a78147ffe0b84de1dffbebed2a6ea965becd5d0bd7faf54f1f29c6b5'

// 签名结果
const sig = sm2.doSignature('123', sk, {userId: 'userid@soie-chain.com', der: false, hash: true})
```

### 带 userid 的签名校验 

```js
let sk = 'f00df601a78147ffe0b84de1dffbebed2a6ea965becd5d0bd7faf54f1f29c6b5'
let valid = sm2.doVerifySignature("123", "344857fe641c9fd3825a389fc85ca8bcab694f199fe155022e17dfe97f36afa43e0f5a06cea4dc170e11a17f0a465cc2ce235b94c24e550d6172764a52eaad71", sm2.getPKFromSK(sk) , {
        hash: true,
        der: false,
        userId: 'userid@soie-chain.com',
    });
```

## sm3

```js
const sm3 = require('@salaku/sm-crypto').sm3;

let hashData = sm3('abc'); // 杂凑
```

## sm4

### 加密

```js
const sm4 = require('@salaku/sm-crypto').sm4;
const key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];

let encryptData = sm4.encrypt([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10], key); // 加密
```

### 解密

```js
const sm4 = require('@salaku/sm-crypto').sm4;
const key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];

let decryptData = sm4.decrypt([0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46], key); // 解密
```

## 协议

MIT
