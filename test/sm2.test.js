const sm2 = require('../index').sm2;

const cipherMode = 1; // 1 - C1C3C2，0 - C1C2C3
const sks = ['f00df601a78147ffe0b84de1dffbebed2a6ea965becd5d0bd7faf54f1f29c6b5', 'b01bb4ceb384ceee3b1eaf2ed78deba989ed92b25c75f28de58fa8bba191d7bc', 'b8bcde6ea12982ff341cef358040584e0b397b51beaf0b11a45f80be9b5dfe33', 'a0f9c0d3c7969ee21412a98da06a9b6c88b66423f7906b121297f2cca6f55231', '4a395b3cd397d007004a7dd71188d549950529e25983d1a2d4c39dffcfa28d8f', 'b43f062ed890a45f2e25ab6eff008b613d8ad98d018f83fa0f7c72e1f3e3b6fa', '368e24f3a2e6042c362c57233044603391b14f428c72b0c19b649ee16fb010fe']
const compressedPKS = ['02b507fe1afd0cc7a525488292beadbe9f143784de44f8bc1c991636509fd50936', '02f9d915954e04107d11fb9689a6330c22199e1e830857bff076e033bbca2888d4', '03cd2875d6381b974bd13c9c6087c08fcf0b9b700ea8c9b601ae35a6a9651fbce2', '03744f32e35e8e45cfa6360b49fe12e730cb294bce40db5099b0de697aa00a3d71', '020f0a0c7fb839a51b1f64cf2b49f9b3269d2b9ca49d3309e3de4453f389c827bb', '02281b065a508bace266556f239e491a44a0a64789c7d4fc333d2a875a7ddc1714', '039608d098f275db24db04211d62f66e1438bdd0d93d7e3dbe33136ef3fc53c726']

const msgString = 'absasdagfadgadsfdfdsf';

let publicKey;
let privateKey;

const TEST_SK = 'f00df601a78147ffe0b84de1dffbebed2a6ea965becd5d0bd7faf54f1f29c6b5'
const DE_COMPRESSED = '04b507fe1afd0cc7a525488292beadbe9f143784de44f8bc1c991636509fd509360cb8e50437a9109cca8b384b499fbb84290b7bcbf4d9ceec33bd829224bc995e'
const COMPRESSED = '02b507fe1afd0cc7a525488292beadbe9f143784de44f8bc1c991636509fd50936'

function bin2str(s){
    if(typeof s === 'string')
        return s
    if(Array.isArray(s))
        s = new Uint8Array(s)
    if(typeof TextEncoder === 'function')
        return new TextEncoder().encode(s)
    if(typeof Buffer === 'function')
        return Buffer.from(s).toString('utf-8')
}

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

    expect(bin2str(decryptData)).toBe(msgString);

    for (let i = 0; i < 100; i++) {
        let encryptData = sm2.doEncrypt(msgString, publicKey, cipherMode);
        let decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode);

        expect(bin2str(decryptData)).toBe(msgString);
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

    // 纯签名 + 生成椭圆曲线点 + sm3杂凑 + 不做公钥推 + 添加userId
    let sigValueHex6 = sm2.doSignature(msgString, privateKey, {
        hash: true,
        publicKey,
        userId: 'userid@soie-chain.com',
    });
    let verifyResult6 = sm2.doVerifySignature(msgString, sigValueHex6, publicKey, {
        hash: true,
        userId: 'userid@soie-chain.com',
    });
    expect(verifyResult6).toBe(true);
    let verifyResult6False = sm2.doVerifySignature(msgString, sigValueHex6, publicKey, {
        hash: true,
        userId: 'wrongTestUserId',
    });
    expect(verifyResult6False).toBe(false);
});


test('compress', () => {
    let i = 0
    sks.forEach(sk => {
        const pk = sm2.getPKFromSK(sk)
        const compressed = sm2.compress(pk)
        expect(compressed).toBe(compressedPKS[i]);
        i++;
    })
})


test('deCompress', () => {
    let i = 0
    sks.forEach(sk => {
        const pk = sm2.getPKFromSK(sk)
        const decompressed = sm2.deCompress(compressedPKS[i])
        expect(decompressed).toBe(pk);
        i++;
    })
})

test('sign with user-id', () => {
    console.log('sig =' + sm2.doSignature('123', TEST_SK, {userId: 'userid@soie-chain.com', der: false, hash: true}))
    console.log('sig =' + sm2.doSignature(new Uint8Array(['1', '2', '3'].map(x => x.charCodeAt(0))), TEST_SK, {userId: 'userid@soie-chain.com', der: false, hash: true}))
})

test('verifySign', () => {
    let valid = sm2.doVerifySignature("123", "cc9101a30035b6c045e6f1f85dddf49f0354e886affc6b7471c34b0b5167b8362c543aa782d74e1e170d9ed66eec92c006ad70c27b9777f1b26c9d9d400b6354", DE_COMPRESSED, {
        hash: true,
        der: false,
        userId: 'userid@soie-chain.com',
    });
    expect(valid).toBe(true)
})

test('encrypt', () => {
    const sk = 'f00df601a78147ffe0b84de1dffbebed2a6ea965becd5d0bd7faf54f1f29c6b5'
    const pk = sm2.getPKFromSK(sk)
    let encrypted = sm2.doEncrypt('123', pk , sm2.C1C2C3)
    console.log(encrypted)
})

test('decrypt', () => {
    const sk = 'f00df601a78147ffe0b84de1dffbebed2a6ea965becd5d0bd7faf54f1f29c6b5'
    const pk = sm2.getPKFromSK(sk)
    let encrypted = '04fc01e760e6a6b21ae205dc3424d4d4889bc097248eb803137273eb4ccd953fb562eb30779390db296bdb73bdff129cbd750d8635814d552f190b4b97876826c7168903a73e5ddf0bfb1247e04ca0835da0792b5b149a3a6034bbe7a3ff4ddc5218dec0'
    const ret = sm2.doDecrypt(encrypted, sk, sm2.C1C2C3)
    console.log(Buffer.from(ret).toString('ascii'))
})
