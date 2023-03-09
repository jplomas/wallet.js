import pkg from 'randombytes';  // eslint-disable-line import/no-extraneous-dependencies
import { cryptoSign, cryptoSignKeypair, cryptoSignOpen, cryptoSignVerify, cryptoSignSignature, CryptoPublicKeyBytes, CryptoSecretKeyBytes, SeedBytes, CryptoBytes } from '@theqrl/dilithium5';
import { SeedBinToMnemonic } from './utils/mnemonic.js';
const {randomBytes} = pkg;

export function New() {
    var pk = new Uint8Array(CryptoPublicKeyBytes);
    var sk = new Uint8Array(CryptoSecretKeyBytes);

    var seed = new Uint8Array(randomBytes(SeedBytes))
    seed = cryptoSignKeypair(seed, pk, sk);
    
    return {
        pk: pk,
        sk: sk,
        seed: seed,
        randomizedSigning: false,
        GetPK: GetPK(),
        GetSK: GetSK(),
        GetSeed: GetSeed(),
        GetHexSeed: GetHexSeed(),
        GetMnemonic: GetMnemonic(),
        Seal: Seal(message),
        Sign: Sign(message),
        GetAddress: GetAddress(),
        Open: Open(signatureMessage, pk),
        Verify: Verify(message, signature, pk),
        ExtractMessage: ExtractMessage(signatureMessage),
        ExtractSignature: ExtractSignature(signatureMessage)
    }
}

export function NewDilithiumFromSeed(seed) {
    var pk = new Uint8Array(CryptoPublicKeyBytes);
    var sk = new Uint8Array(CryptoSecretKeyBytes);

    seed = cryptoSignKeypair(seed, pk, sk);
    return {
        pk: pk,
        sk: sk,
        seed: seed,
        randomizedSigning: false,
        GetPK: GetPK(),
        GetSK: GetSK(),
        GetSeed: GetSeed(),
        GetHexSeed: GetHexSeed(),
        GetMnemonic: GetMnemonic(),
        Seal: Seal(message),
        Sign: Sign(message),
        GetAddress: GetAddress(),
        Open: Open(signatureMessage, pk),
        Verify: Verify(message, signature, pk),
        ExtractMessage: ExtractMessage(signatureMessage),
        ExtractSignature: ExtractSignature(signatureMessage)
    }
}

function GetPK() {
    return this.pk
}

function GetSK() {
    return this.sk
}

function GetSeed() {
    return this.seed
}

function GetHexSeed() {
    return '0x'+this.seed.toString(16)
}

function  GetMnemonic() {
    return SeedBinToMnemonic(this.seed)
}

// Seal the message, returns signature attached with message.
function Seal(message) {
    return cryptoSign(message, this.sk, this.randomizedSigning)
}

// Sign the message, and return a detached signature. Detached signatures are
// variable sized, but never larger than SIG_SIZE_PACKED.
function Sign(message) {
    let sm = cryptoSign(message)
    var signature = new Uint8Array(CryptoBytes)
    signature = sm.slice(0, CryptoBytes)
    return signature
}

function GetAddress() {
    return GetDilithiumAddressFromPK(this.pk)
}

// Open the sealed message m. Returns the original message sealed with signature.
// In case the signature is invalid, nil is returned.
function Open(signatureMessage, pk){
	return cryptoSignOpen(signatureMessage, pk)
}

function Verify(message, signature, pk) {
	return cryptoSignVerify(signature, message, pk)
}

// ExtractMessage extracts message from Signature attached with message.
function ExtractMessage(signatureMessage) {
	return signatureMessage.slice(CryptoBytes, signatureMessage.length - 1)
}

// ExtractSignature extracts signature from Signature attached with message.
function ExtractSignature(signatureMessage) {
	return signatureMessage.slice(0, CryptoBytes)
}

function GetDilithiumDescriptor() {
	/*
		In case of Dilithium address, it doesn't have any choice of hashFunction,
		height, addrFormatType. Thus keeping all those values to 0 and assigning
		only signatureType in the descriptor.
	*/
	return 3 << 4
}

function GetDilithiumAddressFromPK(pk) {
    let addressSize = 20
	var address = new Uint8Array(addressSize)
	let descBytes = GetDilithiumDescriptor()
	address[0] = descBytes

	var hashedKey = new SHAKE(256)
    hashedKey.update(pk)
    hashedKey.digest({ buffer: Buffer.alloc(32), format: 'hex' })
    address = address.slice(0,1)
    address.push(...hashedKey.slice(hashedKey.length-addressSize+1))

	return address
}

function IsValidDilithiumAddress(address) {
	let d = GetDilithiumDescriptor()
	if (address[0] != d) {
		return false
	}

	// TODO: Add checksum
	return true
}
