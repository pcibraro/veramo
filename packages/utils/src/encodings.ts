import * as u8a from 'uint8arrays'
import { bases } from 'multiformats/basics'

export function bytesToBase64url(b: Uint8Array): string {
  return u8a.toString(b, 'base64url')
}

export function base64ToBytes(s: string): Uint8Array {
  const inputBase64Url = s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
  return u8a.fromString(inputBase64Url, 'base64url')
}

export function bytesToBase64(b: Uint8Array): string {
  return u8a.toString(b, 'base64pad')
}

export function encodeBase64url(s: string): string {
  return bytesToBase64url(u8a.fromString(s))
}

export function decodeBase64url(s: string): string {
  return u8a.toString(base64ToBytes(s))
}

export function encodeJoseBlob(payload: {}) {
  return u8a.toString(u8a.fromString(JSON.stringify(payload), 'utf-8'), 'base64url')
}

export function decodeJoseBlob(blob: string) {
  return JSON.parse(u8a.toString(u8a.fromString(blob, 'base64url'), 'utf-8'))
}

export function bytesToMultibase(b: Uint8Array, base: keyof typeof bases = 'base58btc'): string {
  return bases[base].encode(b)
}

export { bases } from 'multiformats/basics'

export function hexToBytes(s: string): Uint8Array {
  const input = s.startsWith('0x') ? s.substring(2) : s
  return u8a.fromString(input.toLowerCase(), 'base16')
}

export function bytesToHex(b: Uint8Array): string {
  return u8a.toString(b, 'base16')
}

export function stringToBytes(s: string): Uint8Array {
  return u8a.fromString(s, 'utf-8')
}

export function bytesToString(b: Uint8Array): string {
  return u8a.toString(b, 'utf-8')
}