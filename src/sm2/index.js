const { BigInteger } = require('../lib/jsbn');
const { encodeDer, decodeDer } = require('./asn1');
const SM3Digest = require('./sm3');
const SM2Cipher = require('./sm2');
const util = require('./utils');

let { G, curve, n } = util.generateEcparam();
const C1C2C3 = 0;

/**
 * 加密
 */
function doEncrypt(msg, publicKey, cipherMode = 1) {
    let cipher = new SM2Cipher();
    msg = typeof msg === 'string' ? util.str2Bin(msg) : msg;
    publicKey = typeof publicKey !== 'string' ? util.bin2Hex(publicKey) : publicKey
    if (publicKey.length > 128) {
      publicKey = publicKey.substr(publicKey.length - 128);
    }
    let xHex = publicKey.substr(0, 64);
    let yHex = publicKey.substr(64);
    publicKey = cipher.createPoint(xHex, yHex);

    let c1 = cipher.initEncipher(publicKey);

    cipher.encryptBlock(msg);
    let c2 = util.bin2Hex(msg);

    let c3 = new Array(32);
    cipher.doFinal(c3)
    c3 = util.bin2Hex(c3);

    let ret = cipherMode === C1C2C3 ? c1 + c2 + c3 : c1 + c3 + c2;
    return '04' + ret
}

/**
 *
 * @param encryptData {string} 十六进制字符串
 * @param privateKey {string}
 * @param cipherMode
 * @returns {[]|*[]}
 */
function doDecrypt(encryptData, privateKey, cipherMode = 1) {
    let cipher = new SM2Cipher();

    privateKey = new BigInteger(privateKey, 16);
    if(encryptData.substr(0, 2) === '04')
        encryptData = encryptData.substr(2, encryptData.length - 2)

    let c1X = encryptData.substr(0, 64);
    let c1Y = encryptData.substr(c1X.length, 64);
    let c1Length = c1X.length + c1Y.length;

    let c2, c3;


    if (cipherMode === C1C2C3) {
        c3 = encryptData.substr(encryptData.length - 64);
        c2 = encryptData.substr(c1Length, encryptData.length - c1Length - 64);
    }else{
        c3 = encryptData.substr(c1Length, 64);
        c2 = encryptData.substr(c1Length + 64);
    }

    let data = util.hex2Bin(c2);

    let c1 = cipher.createPoint(c1X, c1Y);
    cipher.initDecipher(privateKey, c1);
    cipher.decryptBlock(data);
    let c3_ = new Array(32);
    cipher.doFinal(c3_);

    let isDecrypt = util.bin2Hex(c3_) === c3;

    if (isDecrypt) {
        return data
    } else {
        return []
    }
}

/**
 * 签名
 *
 */
function doSignature(msg, privateKey, { pointPool, der, hash, publicKey, userId } = {}) {
    if(typeof privateKey !== 'string')
        privateKey = util.bin2Hex(privateKey)

    let hashHex = typeof msg === 'string' ? util.parseUtf8StringToHex(msg) : util.bin2Hex(msg);

    if (hash) {
        // sm3杂凑
        publicKey = publicKey || getPublicKeyFromPrivateKey(privateKey);
        hashHex = doSm3Hash(hashHex, publicKey, userId);
    }

    let dA = new BigInteger(privateKey, 16);
    let e = new BigInteger(hashHex, 16);

    // k
    let k = null;
    let r = null;
    let s = null;

    do {
        do {
            let point;
            if (pointPool && pointPool.length) {
                point = pointPool.pop();
            } else {
                point = getPoint();
            }
            k = point.k;

            // r = (e + x1) mod n
            r = e.add(point.x1).mod(n);
        } while (r.equals(BigInteger.ZERO) || r.add(k).equals(n));

        // s = ((1 + dA)^-1 * (k - r * dA)) mod n
        s = dA.add(BigInteger.ONE).modInverse(n).multiply(k.subtract(r.multiply(dA))).mod(n);
    } while (s.equals(BigInteger.ZERO));

    if (der) {
        // asn1 der编码
        return encodeDer(r, s);
    }

    return util.leftPad(r.toString(16), 64) + util.leftPad(s.toString(16), 64);
}

/**
 * 验签
 */
function doVerifySignature(msg, signHex, publicKey, { der, hash, userId } = {}) {
    let hashHex = typeof msg === 'string' ? util.parseUtf8StringToHex(msg) : util.bin2Hex(msg);
    if(typeof signHex !== 'string')
        signHex = util.bin2Hex(signHex)

    if (hash) {
        // sm3杂凑
        hashHex = doSm3Hash(hashHex, publicKey, userId);
    }

    let r, s;
    if (der) {
        let decodeDerObj = decodeDer(signHex);
        r = decodeDerObj.r;
        s = decodeDerObj.s;
    } else {
        r = new BigInteger(signHex.substring(0, 64), 16);
        s = new BigInteger(signHex.substring(64), 16);
    }

    let PA = curve.decodePointHex(publicKey);
    let e = new BigInteger(hashHex, 16);

    // t = (r + s) mod n
    let t = r.add(s).mod(n);

    if (t.equals(BigInteger.ZERO)) return false;

    // x1y1 = s * G + t * PA
    let x1y1 = G.multiply(s).add(PA.multiply(t));

    // R = (e + x1) mod n
    let R = e.add(x1y1.getX().toBigInteger()).mod(n);

    return r.equals(R);
}

/**
 * sm3杂凑算法
 * 计算M值: Hash(za || msg)
 */
function doSm3Hash(hashHex, publicKey, userId) {
    let smDigest = new SM3Digest();

    let z = new SM3Digest().getZ(G, publicKey.substr(2, 128), userId);
    let zValue = util.hex2Bin(util.bin2Hex(z));

    let p = hashHex;
    let pValue = util.hex2Bin(p);

    let hashData = new Array(smDigest.getDigestSize());
    smDigest.blockUpdate(zValue, 0, zValue.length);
    smDigest.blockUpdate(pValue, 0, pValue.length);
    smDigest.doFinal(hashData, 0);

    return util.bin2Hex(hashData)
}

/**
 * 计算公钥
 */
function getPublicKeyFromPrivateKey(privateKey) {
    let PA = G.multiply(new BigInteger(privateKey, 16));
    let x = util.leftPad(PA.getX().toBigInteger().toString(16), 64);
    let y = util.leftPad(PA.getY().toBigInteger().toString(16), 64);
    return '04' + x + y;
}

/**
 * 获取椭圆曲线点
 */
function getPoint() {
    let keypair = util.generateKeyPairHex();
    let PA = curve.decodePointHex(keypair.publicKey);

    keypair.k = new BigInteger(keypair.privateKey, 16);
    keypair.x1 = PA.getX().toBigInteger();

    return keypair;
}

module.exports = {
    generateKeyPairHex: util.generateKeyPairHex,
    doEncrypt,
    doDecrypt,
    doSignature,
    doVerifySignature,
    getPoint,
    compress: util.compress,
    getPKFromSK: util.getPKFromSK,
    deCompress: util.deCompress,
    C1C2C3: C1C2C3,
    C1C3C2: 1
};
