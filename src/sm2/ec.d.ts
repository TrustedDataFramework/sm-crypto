import { BigInteger} from "../lib/jsbn";

export class ECFieldElementFp {
    x: BigInteger
    q: BigInteger

    constructor(q: BigInteger, x: BigInteger)

    equals(other: any): boolean

    /**
     * 返回具体数值
     */
    toBigInteger() : BigInteger

    negate(): ECFieldElementFp

    add(b: ECFieldElementFp): ECFieldElementFp

    subtract(b: ECFieldElementFp): ECFieldElementFp

    multiply(b: ECFieldElementFp): ECFieldElementFp

    divide(b: ECFieldElementFp): ECFieldElementFp

    square(): ECFieldElementFp
}

export class ECPointFp{
    constructor(curve: ECCurveFp, x: ECFieldElementFp, y: ECFieldElementFp, z: BigInteger)

    equals(other: any): boolean

    getX(): BigInteger
    getY(): BigInteger

    /**
     * 是否是无穷远点
     */
    isInfinity(): boolean

    /**
     * 取反，x 轴对称点
     */
    negate(): ECPointFp


    add(b: ECPointFp): ECPointFp

    twice(): ECPointFp

    multiply(k: BigInteger): ECPointFp
}

export class ECCurveFp{
    q: BigInteger
    a: ECFieldElementFp
    b: ECFieldElementFp
    infinity: ECPointFp
    constructor(q: BigInteger, a: BigInteger, b: BigInteger)
    equals(other: any): boolean

    /**
     * 生成椭圆曲线域元素
     */
    fromBigInteger(x: BigInteger): ECFieldElementFp

    decodePointHex(s: string): ECPointFp
}