const { BigInteger, SecureRandom } = require('../lib/jsbn');
const { ECCurveFp, ECFieldElementFp } = require('./ec');
let rng = new SecureRandom();
let { curve, G, n } = generateEcparam();

const THREE = new BigInteger('3');

function hexToInt(x) {
    if (48 <= x && x <= 57) return x - 48;
    if (97 <= x && x <= 102) return x - 87;
    if (65 <= x && x <= 70) return x - 55;
    return 0;
}


function hex2Bin(s){
    if(s instanceof Uint8Array)
        return s
    if(s instanceof ArrayBuffer || Array.isArray(s))
        return new Uint8Array(s)
    if(typeof s !== 'string')
        throw new Error('invalid type')
    if(s.startsWith('0x'))
        s = s.slice(2)
    if(typeof Buffer === 'function')
        return Buffer.from(s, 'hex')
    if(s.length % 2 !== 0)
        throw new Error('invalid hex ' + s)

    const ret = new Uint8Array(s.length / 2)
    for (let i = 0; i < s.length / 2; i++) {
        const h = s.charCodeAt(i * 2);
        const l = s.charCodeAt(i * 2 + 1);
        ret[i] = (hexToInt(h) << 4) + hexToInt(l);
    }
    return ret;
}

function compress(publicKey) {
    if (publicKey.slice(0, 2) !== '04')
        return publicKey;
    const b = hex2Bin(publicKey)
    const x = publicKey.slice(2, 2 + 64)
    return (b[b.length - 1] & 1 ? '03' : '02') + x
}


function deCompress(pk) {
    if (pk.slice(0, 2) === '04')
        return pk

    const x = pk.slice(2)
    const xBig = new BigInteger(x, 16)

    const p14 = curve.q.add(BigInteger.ONE).divide(new BigInteger('4'))
    const alpha = xBig.pow(THREE).add(curve.a.x.multiply(xBig)).add(curve.b.x).mod(curve.q)
    let beta = alpha.modPow(p14, curve.q)
    if(pk.slice(0, 2) === '03')
        beta = curve.q.subtract(beta)
    let yHex = beta.toString(16)
    while (yHex.length < 64)
        yHex = '0' + yHex
    return '04' + bin2hex(x) + yHex
}


/**
 * 获取公共椭圆曲线
 */
function getGlobalCurve() {
    return curve;
}

/**
 * 生成ecparam
 */
function generateEcparam() {
    // 椭圆曲线
    let p = new BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16);
    let a = new BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16);
    let b = new BigInteger('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', 16);
    let curve = new ECCurveFp(p, a, b);

    // 基点
    let gxHex = '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7';
    let gyHex = 'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0';
    let G = curve.decodePointHex('04' + gxHex + gyHex);

    let n = new BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16);

    return { curve, G, n };
}

/**
 * 生成密钥对
 */
function generateKeyPairHex() {
    let d = new BigInteger(n.bitLength(), rng).mod(n.subtract(BigInteger.ONE)).add(BigInteger.ONE); // 随机数
    let privateKey = leftPad(d.toString(16), 64);

    let P = G.multiply(d); // P = dG，p 为公钥，d 为私钥
    let Px = leftPad(P.getX().toBigInteger().toString(16), 64);
    let Py = leftPad(P.getY().toBigInteger().toString(16), 64);
    let publicKey = '04' + Px + Py;

    return { privateKey, publicKey };
}

/**
 * 解析utf8字符串到16进制
 */
function parseUtf8StringToHex(input) {
    if(typeof Buffer === 'function')
        return Buffer.from(input, 'utf-8').toString('hex')
    return bin2hex(str2Bin(input))
}

function bin2hex(input){
    if(typeof input === 'string')
        return input
    if(
        !(input instanceof ArrayBuffer) &&
        !(input instanceof Uint8Array) &&
        !Array.isArray(input)
    )
        throw new Error("input " + input + " is not ArrayBuffer Uint8Array or Buffer and other array-like ")
    if(!input instanceof Uint8Array)
        input = new Uint8Array(input)
    // input maybe Buffer or Uint8Array
    if(typeof Buffer === 'function')
        return Buffer.from(input).toString('hex')
    return Array.prototype.map.call(input, x => ('00' + x.toString(16)).slice(-2)).join('');
}

/**
 * 补全16进制字符串
 */
function leftPad(input, num) {
    if (input.length >= num) return input;

    return (new Array(num - input.length + 1)).join('0') + input
}

/**
 * 转成16进制串
 */
function arrayToHex(arr) {
    let words = [];
    let j = 0;
    for (let i = 0; i < arr.length * 2; i += 2) {
        words[i >>> 3] |= parseInt(arr[j], 10) << (24 - (i % 8) * 4);
        j++;
    }

    // 转换到16进制
    let hexChars = [];
    for (let i = 0; i < arr.length; i++) {
        let bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
        hexChars.push((bite >>> 4).toString(16));
        hexChars.push((bite & 0x0f).toString(16));
    }

    return hexChars.join('');
}

/**
 * 转成utf8串
 */
function arrayToUtf8(arr) {
    let words = [];
    let j = 0;
    for (let i = 0; i < arr.length * 2; i += 2) {
        words[i >>> 3] |= parseInt(arr[j], 10) << (24 - (i % 8) * 4);
        j++
    }

    try {
        let latin1Chars = [];

        for (let i = 0; i < arr.length; i++) {
            let bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
            latin1Chars.push(String.fromCharCode(bite));
        }

        return decodeURIComponent(escape(latin1Chars.join('')));
    } catch (e) {
        throw new Error('Malformed UTF-8 data');
    }
}

/**
 * 转成ascii码数组
 */
function hexToArray(hexStr) {
    let words = [];
    let hexStrLength = hexStr.length;

    if (hexStrLength % 2 !== 0) {
        hexStr = leftPad(hexStr, hexStrLength + 1);
    }

    hexStrLength = hexStr.length;

    for (let i = 0; i < hexStrLength; i += 2) {
        words.push(parseInt(hexStr.substr(i, 2), 16));
    }
    return words
}

/**
 * 计算公钥
 */
function getPKFromSK(privateKey) {
    let PA = G.multiply(new BigInteger(privateKey, 16));
    let x = leftPad(PA.getX().toBigInteger().toString(16), 64);
    let y = leftPad(PA.getY().toBigInteger().toString(16), 64);
    return '04' + x + y;
}

function str2Bin(str){
    if(typeof Buffer === 'function')
        return Buffer.from(str, 'utf-8')
    if(typeof TextEncoder === 'function')
        return new TextEncoder().encode(str)
}

module.exports = {
    getGlobalCurve,
    generateEcparam,
    generateKeyPairHex,
    parseUtf8StringToHex,
    leftPad,
    arrayToUtf8,
    compress,
    getPKFromSK,
    deCompress,
    bin2Hex: bin2hex,
    hex2Bin: hex2Bin,
    str2Bin: str2Bin
}
