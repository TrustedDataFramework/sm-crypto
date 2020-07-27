const { BigInteger, SecureRandom } = require('jsbn');
const { ECCurveFp } = require('./ec');
const Buffer = require('safe-buffer').Buffer
const _BigInteger = require('bigi')
let rng = new SecureRandom();
let { curve, G, n } = generateEcparam();
const ecurve = require('ecurve');
const Curve = ecurve.Curve;
const GLOBAL = window || global;

const CURVE_PARAMS = {
    "p": "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff",
    "a": "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc",
    "b": "28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93",
    "n": "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123",
    "h": "01",
    "Gx": "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
    "Gy": "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"
}

const CURVE = new Curve(
    new _BigInteger(CURVE_PARAMS.p, 16),
    new _BigInteger(CURVE_PARAMS.a, 16),
    new _BigInteger(CURVE_PARAMS.b, 16),
    new _BigInteger(CURVE_PARAMS.Gx, 16),
    new _BigInteger(CURVE_PARAMS.Gy, 16),
    new _BigInteger(CURVE_PARAMS.n, 16),
    new _BigInteger(CURVE_PARAMS.h, 16)
);

function compress(publicKey) {
    if (publicKey.slice(0, 2) !== '04')
        return publicKey;
    let P = curve.decodePointHex(publicKey)
    let x = leftPad(P.getX().toBigInteger().toString(16), 64);
    const yPrefix = P.getY().toBigInteger() ? "02" : "03";
    return yPrefix + x;
}


function deCompress(pk) {
    if (pk.slice(0, 2) === '04')
        return pk;

    return '04' +
        pk.slice(2) +
        ecurve.Point
            .decodeFrom(CURVE, Buffer.from(pk, "hex"))
            .affineY.toBuffer(32).toString('hex')
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
    input = unescape(encodeURIComponent(input));

    let length = input.length;

    // 转换到字数组
    let words = [];
    for (let i = 0; i < length; i++) {
        words[i >>> 2] |= (input.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
    }

    // 转换到16进制
    let hexChars = [];
    for (let i = 0; i < length; i++) {
        let bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
        hexChars.push((bite >>> 4).toString(16));
        hexChars.push((bite & 0x0f).toString(16));
    }

    return hexChars.join('');
}

/**
 * 解析arrayBuffer到16进制字符串
 */
function parseArrayBufferToHex(input) {
    return Array.prototype.map.call(new Uint8Array(input), x => ('00' + x.toString(16)).slice(-2)).join('');
}


function buf2Hex(input){
    if(
        !(input instanceof ArrayBuffer) &&
        !(input instanceof Uint8Array) &&
        !(GLOBAL && GLOBAL['Buffer'] && input instanceof GLOBAL['Buffer']) &&
        !(input instanceof Array)
    )
        throw new Error("input " + input + " is not ArrayBuffer Uint8Array or Buffer and other array-like ")
    if(input instanceof ArrayBuffer)
        input = new Uint8Array(input)
    // input maybe Buffer or Uint8Array
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

module.exports = {
    getGlobalCurve,
    generateEcparam,
    generateKeyPairHex,
    parseUtf8StringToHex,
    parseArrayBufferToHex,
    leftPad,
    arrayToHex,
    arrayToUtf8,
    hexToArray,
    compress,
    getPKFromSK,
    deCompress,
    buf2Hex
};
