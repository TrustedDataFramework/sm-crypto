import { KeyPair } from './utils'

export function generateKeyPairHex(): KeyPair
export const C1C2C3 = 0
export const C1C3C2 = 1

export declare type CipherMode = 0 | 1

export function doEncrypt(msg: string | Uint8Array | ArrayBuffer | number[], publicKey: string | Uint8Array | ArrayBuffer | number[], mode: CipherMode): string

export function doDecrypt(enc: string, privateKey: string | Uint8Array | ArrayBuffer | number[], mode?: CipherMode): string

export function doSignature(
    msg: string | Uint8Array | ArrayBuffer | number[],
    privateKey: string | Uint8Array | ArrayBuffer | number[],
    opts?: SignOptions
): string

export interface SignOptions{
    der?: boolean
    hash?: boolean
    userId?: string | Uint8Array | ArrayBuffer | number[]
}

export function doVerifySignature(
    msg: string | Uint8Array | ArrayBuffer | number[],
    signHex: string | Uint8Array | ArrayBuffer | number[],
    publicKey: string | Uint8Array | ArrayBuffer | number[],
    opts?: SignOptions
): boolean

export function compress(pk: string): string

export function getPKFromSK(sk: string): string

export function deCompress(pk: string): string

export function getPKFromSK(sk: string): string

