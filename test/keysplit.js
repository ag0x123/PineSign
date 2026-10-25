/**
 * The split key.
 *
 * What is being tested is a negative: that neither half opens the file. The
 * positive case — both halves, correct plaintext — is the easy one and would
 * pass even if the split were a formality.
 */

import { secp256k1 } from '@noble/curves/secp256k1'
import {
  ephemeral, recipientHalf, xor, encryptFile, decryptFile,
  encryptDescription, decryptDescription, transferId, splitPublicKey, joinPublicKey,
  commitToWord, hash, SALT_BYTES,
} from '../shared/keysplit.js'
import { toHex } from '../shared/crypto.js'

let pass = 0, fail = 0
const check = (label, condition) => {
  console.log(`${condition ? '  ok  ' : ' FAIL '} ${label}`)
  condition ? pass++ : fail++
}
const same = (a, b) => Buffer.from(a).equals(Buffer.from(b))
const refuses = (fn) => {
  try {
    fn()
    return false
  } catch {
    return true
  }
}

const ID = '0x' + '11'.repeat(32)
const file = new TextEncoder().encode('the quiet part, written down')

// Bob's published key, and a fresh ephemeral for this transfer.
const bobSecret = secp256k1.utils.randomPrivateKey()
const bobPublic = secp256k1.getPublicKey(bobSecret, true)
const eA = ephemeral()

console.log('\nthe halves')
const aFromSender = recipientHalf({ secretKey: eA.secretKey, theirPublicKey: bobPublic, transferId: ID })
const aFromRecipient = recipientHalf({ secretKey: bobSecret, theirPublicKey: eA.publicKey, transferId: ID })
check('both sides derive the same A', same(aFromSender, aFromRecipient))
check('A is 32 bytes', aFromSender.length === 32)

// The salt is what makes one pair of keys yield a different A per transfer.
const other = recipientHalf({
  secretKey: eA.secretKey,
  theirPublicKey: bobPublic,
  transferId: '0x' + '22'.repeat(32),
})
check('a different transfer gives a different A', !same(aFromSender, other))

const stranger = secp256k1.utils.randomPrivateKey()
const strangerA = recipientHalf({
  secretKey: stranger,
  theirPublicKey: eA.publicKey,
  transferId: ID,
})
check('somebody else derives a different A', !same(aFromSender, strangerA))

console.log('\nthe file')
const sealed = encryptFile(file)
const B = xor(sealed.key, aFromSender)
check('K is 32 bytes', sealed.key.length === 32)
check('B is 32 bytes', B.length === 32)
check('A XOR B is K', same(xor(aFromRecipient, B), sealed.key))

const opened = decryptFile(sealed.ciphertext, xor(aFromRecipient, B))
check('both halves open the file', same(opened.plaintext, file))
check('and recover the same preimage', same(opened.plaintextHash, sealed.plaintextHash))
check('the salt comes back', opened.salt.length === SALT_BYTES)

// The point of the whole exercise.
check('A alone does not open it', refuses(() => decryptFile(sealed.ciphertext, aFromRecipient)))
check('B alone does not open it', refuses(() => decryptFile(sealed.ciphertext, B)))
check('the ciphertext is not the plaintext', !same(sealed.ciphertext.slice(0, file.length), file))

// The same file twice must not look the same, or the commitment leaks it.
const again = encryptFile(file)
check('the same file commits to a different value', !same(again.plaintextHash, sealed.plaintextHash))
check('and encrypts to different bytes', !same(again.ciphertext, sealed.ciphertext))

// A tampered ciphertext must fail loudly rather than return rubbish.
const tampered = Uint8Array.from(sealed.ciphertext)
tampered[tampered.length - 1] ^= 0x01
check('a tampered ciphertext is refused', refuses(() => decryptFile(tampered, sealed.key)))

console.log('\nthe description')
const d = encryptDescription('one invoice, 40kb', aFromSender)
check('the recipient can read it before accepting', decryptDescription(d, aFromRecipient) === 'one invoice, 40kb')
check('B does not read it', refuses(() => decryptDescription(d, B)))
check('a stranger does not read it', refuses(() => decryptDescription(d, strangerA)))

console.log('\ncommitments')
check('a commitment is over 32 bytes only', refuses(() => commitToWord(new Uint8Array(31))))
check('committing is deterministic', commitToWord(B) === commitToWord(B))
check('and distinguishes halves', commitToWord(B) !== commitToWord(aFromSender))
check('hash is 0x-prefixed keccak', /^0x[0-9a-f]{64}$/.test(hash(sealed.ciphertext)))

console.log('\nkeys on chain')
const split = splitPublicKey(bobPublic)
check('a compressed key splits into x and a parity bit', /^0x[0-9a-f]{64}$/.test(split.x))
check('and joins back to the same key', same(joinPublicKey(split), bobPublic))
check('an uncompressed key is refused', refuses(() => splitPublicKey(secp256k1.getPublicKey(bobSecret, false))))

console.log('\nthe transfer id')
const fields = {
  sender: '0x' + '0a'.repeat(20),
  passkeyX: '0x' + '01'.repeat(32),
  passkeyY: '0x' + '02'.repeat(32),
  pkBX: split.x,
  pkBOdd: split.odd,
  ephemeralX: splitPublicKey(eA.publicKey).x,
  ephemeralOdd: splitPublicKey(eA.publicKey).odd,
  ciphertextHash: hash(sealed.ciphertext),
  plaintextCommitment: commitToWord(sealed.plaintextHash),
  descriptionHash: hash(d),
  acceptBy: 1700000000n,
  releaseBy: 1700003600n,
}
const id = transferId(fields)
check('an id is a 32-byte hash', /^0x[0-9a-f]{64}$/.test(id))
check('it is deterministic', transferId(fields) === id)
check('one changed field changes it', transferId({ ...fields, acceptBy: 1700000001n }) !== id)
check('a changed parity bit changes it', transferId({ ...fields, pkBOdd: !fields.pkBOdd }) !== id)
check('a wrong-width field is refused', refuses(() => transferId({ ...fields, passkeyX: '0x1234' })))

console.log(`\n${pass} passed, ${fail} failed  (keysplit)\n`)
process.exit(fail === 0 ? 0 : 1)
