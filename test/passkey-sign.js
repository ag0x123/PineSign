/**
 * Turning a browser's assertion into something the contract can check.
 *
 * Two things here have bitten real deployments: DER integers that carry a
 * sign byte or come up short, and high-s signatures. Both are tested against
 * real P-256 signatures rather than fixtures.
 */

import { p256 } from '@noble/curves/p256'
import { fromDer, fieldOffsets, originFrom } from '../shared/passkey-sign.js'

let pass = 0, fail = 0
const check = (label, condition) => {
  console.log(`${condition ? '  ok  ' : ' FAIL '} ${label}`)
  condition ? pass++ : fail++
}
const refuses = (fn) => {
  try {
    fn()
    return false
  } catch {
    return true
  }
}
const joined = ({ r, s }) => Buffer.concat([Buffer.from(r), Buffer.from(s)])

console.log('\nDER signatures')
// Many signatures, because the sign-byte and short-integer cases only show up
// for particular values and a single fixture would miss them.
let allMatched = true
let sawShort = false
for (let i = 0; i < 1000; i++) {
  const secret = p256.utils.randomPrivateKey()
  const signature = p256.sign(new Uint8Array(32).fill(i % 256), secret)
  const der = signature.toDERRawBytes()
  if (der.length !== 70) sawShort = true // a leading zero was stripped somewhere
  if (!joined(fromDer(der)).equals(Buffer.from(signature.toCompactRawBytes()))) {
    allMatched = false
    console.log(`   mismatch at ${i}`)
    break
  }
}
check('a thousand signatures parse to the right (r, s)', allMatched)
check('including ones whose DER is not the usual length', sawShort)

const secret = p256.utils.randomPrivateKey()
const low = p256.sign(new Uint8Array(32).fill(7), secret)
const high = new p256.Signature(low.r, p256.CURVE.n - low.s)
check('low-s parses', joined(fromDer(low.toDERRawBytes())).equals(Buffer.from(low.toCompactRawBytes())))
check('high-s parses too', joined(fromDer(high.toDERRawBytes())).equals(Buffer.from(high.toCompactRawBytes())))
check('and is not silently normalised', !joined(fromDer(high.toDERRawBytes())).equals(Buffer.from(low.toCompactRawBytes())))

check('both halves are 32 bytes', fromDer(low.toDERRawBytes()).r.length === 32 && fromDer(low.toDERRawBytes()).s.length === 32)

console.log('\nmalformed signatures')
check('garbage is refused', refuses(() => fromDer(new Uint8Array([1, 2, 3]))))
check('an empty signature is refused', refuses(() => fromDer(new Uint8Array(0))))
check('a truncated sequence is refused', refuses(() => fromDer(new Uint8Array([0x30, 0x44, 0x02, 0x20]))))
check('a missing second integer is refused', refuses(() => fromDer(
  new Uint8Array([0x30, 0x24, 0x02, 0x20, ...new Array(32).fill(1)]),
)))
check('an integer that runs past the end is refused', refuses(() => fromDer(
  new Uint8Array([0x30, 0x44, 0x02, 0x40, 1, 2, 3]),
)))
check('an oversized integer is refused', refuses(() => fromDer(
  new Uint8Array([0x30, 0x48, 0x02, 0x22, ...new Array(34).fill(9), 0x02, 0x20, ...new Array(32).fill(1)]),
)))

console.log('\nclientDataJSON offsets')
// Key order differs between browsers, which is exactly why the offsets are
// found rather than assumed.
const chrome = '{"type":"webauthn.get","challenge":"abc","origin":"https://v1.id.example.com","crossOrigin":false}'
const reordered = '{"origin":"https://v1.id.example.com","challenge":"abc","type":"webauthn.get"}'
const withExtras = '{"type":"webauthn.get","challenge":"abc","origin":"https://v1.id.example.com","crossOrigin":false,"other":{"a":1}}'

for (const [name, json] of [['chrome-shaped', chrome], ['reordered', reordered], ['with extra fields', withExtras]]) {
  const at = fieldOffsets(json)
  const okType = json.startsWith('"type":"webauthn.get"', at.typeIndex)
  const okChallenge = json.startsWith('"challenge":"', at.challengeIndex)
  const okOrigin = json.startsWith('"origin":"', at.originIndex)
  check(`${name}: every offset lands on its field`, okType && okChallenge && okOrigin)
  check(`${name}: the origin reads back`, originFrom(json) === 'https://v1.id.example.com')
}

check('a create ceremony is refused', refuses(() => fieldOffsets('{"type":"webauthn.create","challenge":"a","origin":"b"}')))
check('a missing origin is refused', refuses(() => fieldOffsets('{"type":"webauthn.get","challenge":"a"}')))

console.log(`\n${pass} passed, ${fail} failed  (passkey-sign)\n`)
process.exit(fail === 0 ? 0 : 1)
