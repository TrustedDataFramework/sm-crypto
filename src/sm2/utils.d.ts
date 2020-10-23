import {ECCurveFp} from "./ec";

export function bin2Hex(buf: ArrayBuffer | Uint8Array | number[] | string): string

export function deCompress(pk: string): string

export function hex2Bin(hex: ArrayBuffer | Uint8Array | number[] | string) : Uint8Array

export function str2Bin(str: string): Uint8Array

export function parseUtf8StringToHex(input: string): string

export function getGlobalCurve(): ECCurveFp

export function generateKeyPairHex(): KeyPair

export function leftPad(input: string, num: number): string

export function compress(pk: string): string

export function getPKFromSK(sk: string): string

export declare interface KeyPair{
    privateKey: string
    publicKey: string
}