const sm2 = require('../index').sm2;

const cipherMode = 1; // 1 - C1C3C2，0 - C1C2C3

// const msgString = 'abcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCDabcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCDabcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCDabcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCDabcdefghABCDEFGH';
const msgString = 'absasdagfadgadsfdfdsf';

let publicKey;
let privateKey;

beforeAll(() => {
    // 生成密钥对
    let keypair = sm2.generateKeyPairHex();

    publicKey = keypair.publicKey;
    privateKey = keypair.privateKey;
});

test('generate keypair', () => {
    expect(publicKey.length).toBe(130);
    expect(privateKey.length).toBe(64);
});

test('encrypt and decrypt data', () => {
    let encryptData = sm2.doEncrypt(msgString, publicKey, cipherMode);
    let decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode);

    expect(decryptData).toBe(msgString);

    for (let i = 0; i < 100; i++) {
        let encryptData = sm2.doEncrypt(msgString, publicKey, cipherMode);
        let decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode);

        expect(decryptData).toBe(msgString);
    }
});

test('sign data and verify sign', () => {
    // 纯签名 + 生成椭圆曲线点
    let sigValueHex = sm2.doSignature(msgString, privateKey);
    let verifyResult = sm2.doVerifySignature(msgString, sigValueHex, publicKey);
    expect(verifyResult).toBe(true);

    // 纯签名
    let sigValueHex2 = sm2.doSignature(msgString, privateKey, {
        pointPool: [sm2.getPoint(), sm2.getPoint(), sm2.getPoint(), sm2.getPoint()],
    });
    let verifyResult2 = sm2.doVerifySignature(msgString, sigValueHex2, publicKey);
    expect(verifyResult2).toBe(true);

    // 纯签名 + 生成椭圆曲线点 + der编解码
    let sigValueHex3 = sm2.doSignature(msgString, privateKey, {
        der: true,
    });
    let verifyResult3 = sm2.doVerifySignature(msgString, sigValueHex3, publicKey, {
        der: true,
    });
    expect(verifyResult3).toBe(true);

    // 纯签名 + 生成椭圆曲线点 + sm3杂凑
    let sigValueHex4 = sm2.doSignature(msgString, privateKey, {
        hash: true,
    });
    let verifyResult4 = sm2.doVerifySignature(msgString, sigValueHex4, publicKey, {
        hash: true,
    });
    expect(verifyResult4).toBe(true);

    for (let i = 0; i < 100; i++) {
        sigValueHex4 = sm2.doSignature(msgString, privateKey, {
            hash: true,
        });
        verifyResult4 = sm2.doVerifySignature(msgString, sigValueHex4, publicKey, {
            hash: true,
        });
        expect(verifyResult4).toBe(true);
    }

    // 纯签名 + 生成椭圆曲线点 + sm3杂凑（不做公钥推导）
    let sigValueHex5 = sm2.doSignature(msgString, privateKey, {
        hash: true,
        publicKey,
    });
    let verifyResult5 = sm2.doVerifySignature(msgString, sigValueHex5, publicKey, {
        hash: true,
        publicKey,
    });
    expect(verifyResult5).toBe(true);
});


test('compress', () => {
    let sk = 'f00df601a78147ffe0b84de1dffbebed2a6ea965becd5d0bd7faf54f1f29c6b5'
    let beforeCompress = sm2.getPKFromSK(sk);
    let compressed = sm2.compress(beforeCompress);
    expect(compressed).toBe('02b507fe1afd0cc7a525488292beadbe9f143784de44f8bc1c991636509fd50936');
})

test('deCompress', () => {
    let deCompressed = '04b507fe1afd0cc7a525488292beadbe9f143784de44f8bc1c991636509fd509360cb8e50437a9109cca8b384b499fbb84290b7bcbf4d9ceec33bd829224bc995e'
    expect(sm2.deCompress('02b507fe1afd0cc7a525488292beadbe9f143784de44f8bc1c991636509fd50936')).toBe(deCompressed)
})
