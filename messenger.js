'use strict'

const {
  bufferToString,
  genRandomSalt,
  generateEG,
  computeDH,
  verifyWithECDSA,
  HMACtoAESKey,
  HMACtoHMACKey,
  HKDF,
  encryptWithGCM,
  decryptWithGCM,
  cryptoKeyToJSON,
  govEncryptionDataStr
} = require('./crypto-primitives')

const { subtle } = require('node:crypto').webcrypto

const MAX_SKIP = 100
const ROOT_INFO = 'ratchet-root-info'
const CHAIN_KEY_CONST = 'chain-key-step'
const MSG_KEY_CONST = 'msg-key-step'

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {}
    this.certs = {}
    this.EGKeyPair = {}
    this.username = null
  }

  /**
   * Canonical string ID for an ECDH/ElGamal public CryptoKey using its JWK coordinates.
   */
  async _pubKeyId (pubKey) {
    if (!pubKey) return null
    const jwk = await cryptoKeyToJSON(pubKey)
    return `${jwk.x}.${jwk.y}`
  }

  async generateCertificate (username) {
    this.username = username
    this.EGKeyPair = await generateEG()
    return {
      username,
      pubKey: this.EGKeyPair.pub
    }
  }

  async receiveCertificate (certificate, signature) {
    const certString = JSON.stringify(certificate)
    const isValid = await verifyWithECDSA(this.caPublicKey, certString, signature)
    if (!isValid) {
      throw new Error('Certificate signature verification failed: potential tampering detected.')
    }
    this.certs[certificate.username] = certificate
  }

  async _kdfChain (chainKey) {
    const nextCK = await HMACtoHMACKey(chainKey, CHAIN_KEY_CONST)
    const mkRaw = await HMACtoAESKey(chainKey, MSG_KEY_CONST, true)
    const mk = await subtle.importKey('raw', mkRaw, 'AES-GCM', true, ['encrypt', 'decrypt'])
    return { nextCK, mk, mkRaw }
  }

  async _skipMessageKeys (state, until) {
    if (state.Nr + MAX_SKIP < until) {
      throw new Error('Too many skipped messages: possible DoS or excessive packet loss.')
    }
    if (state.CKr !== null) {
      const dhId = await this._pubKeyId(state.DHr)
      while (state.Nr < until) {
        const { nextCK, mk } = await this._kdfChain(state.CKr)
        state.CKr = nextCK
        state.MKSKIPPED[`${dhId}:${state.Nr}`] = mk
        state.Nr += 1
      }
    }
  }

  async _dhRatchet (state, remotePubKey) {
    state.PN = state.Ns
    state.Ns = 0
    state.Nr = 0
    state.DHr = remotePubKey

    const dhRecv = await computeDH(state.DHs.sec, state.DHr)
    const [rk1, ckr] = await HKDF(dhRecv, state.RK, ROOT_INFO)
    state.RK = rk1
    state.CKr = ckr

    state.DHs = await generateEG()
    const dhSend = await computeDH(state.DHs.sec, state.DHr)
    const [rk2, cks] = await HKDF(dhSend, state.RK, ROOT_INFO)
    state.RK = rk2
    state.CKs = cks
  }

  async sendMessage (name, plaintext) {
    if (!this.certs[name]) {
      throw new Error(`No verified certificate found for recipient: ${name}`)
    }

    let state = this.conns[name]

    // Initialize session as first sender (Alice role)
    if (!state) {
      const bobPubKey = this.certs[name].pubKey
      const initialSK = await computeDH(this.EGKeyPair.sec, bobPubKey)
      const DHs = await generateEG()
      const dhOut = await computeDH(DHs.sec, bobPubKey)
      const [RK, CKs] = await HKDF(dhOut, initialSK, ROOT_INFO)

      state = {
        DHs,
        DHr: bobPubKey,
        RK,
        CKs,
        CKr: null,
        Ns: 0,
        Nr: 0,
        PN: 0,
        MKSKIPPED: {}
      }
      this.conns[name] = state
    }

    const { nextCK, mk, mkRaw } = await this._kdfChain(state.CKs)
    state.CKs = nextCK

    // Government surveillance encryption
    const govEphemeral = await generateEG()
    const govSharedSecret = await computeDH(govEphemeral.sec, this.govPublicKey)
    const govAESKey = await HMACtoAESKey(govSharedSecret, govEncryptionDataStr)
    const ivGov = genRandomSalt()
    const cGov = await encryptWithGCM(govAESKey, mkRaw, ivGov)

    const receiverIV = genRandomSalt()
    const header = {
      dh: state.DHs.pub,
      pn: state.PN,
      n: state.Ns,
      vGov: govEphemeral.pub,
      cGov,
      ivGov,
      receiverIV
    }

    state.Ns += 1

    const ciphertext = await encryptWithGCM(mk, plaintext, receiverIV, JSON.stringify(header))
    return [header, ciphertext]
  }

  async receiveMessage (name, [header, ciphertext]) {
    if (!this.certs[name]) {
      throw new Error(`No verified certificate found for sender: ${name}`)
    }

    let state = this.conns[name]

    // Initialize session as first receiver (Bob role)
    if (!state) {
      const alicePubKey = this.certs[name].pubKey
      const initialSK = await computeDH(this.EGKeyPair.sec, alicePubKey)
      state = {
        DHs: this.EGKeyPair,
        DHr: null,
        RK: initialSK,
        CKs: null,
        CKr: null,
        Ns: 0,
        Nr: 0,
        PN: 0,
        MKSKIPPED: {}
      }
      this.conns[name] = state
    }

    const headerStr = JSON.stringify(header)
    const incomingDhId = await this._pubKeyId(header.dh)
    const skipId = `${incomingDhId}:${header.n}`

    // 1. Check skipped message keys (out-of-order messages)
    if (state.MKSKIPPED[skipId]) {
      const mk = state.MKSKIPPED[skipId]
      delete state.MKSKIPPED[skipId]
      const plaintextBuf = await decryptWithGCM(mk, ciphertext, header.receiverIV, headerStr)
      return bufferToString(plaintextBuf)
    }

    // 2. Check if sender rotated their DH ratchet key
    const currentDhrId = await this._pubKeyId(state.DHr)
    if (incomingDhId !== currentDhrId) {
      await this._skipMessageKeys(state, header.pn)
      await this._dhRatchet(state, header.dh)
    }

    // 3. Skip any missing messages on the current receiving chain
    await this._skipMessageKeys(state, header.n)

    if (!state.CKr) {
      throw new Error('Receiving chain not initialized or invalid message.')
    }

    // 4. Advance receiving chain and decrypt
    const { nextCK, mk } = await this._kdfChain(state.CKr)
    state.CKr = nextCK
    state.Nr += 1

    const plaintextBuf = await decryptWithGCM(mk, ciphertext, header.receiverIV, headerStr)
    return bufferToString(plaintextBuf)
  }
}

module.exports = {
  MessengerClient
}