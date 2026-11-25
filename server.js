'use strict'

const http = require('node:http')
const fs = require('node:fs')
const path = require('node:path')
const { subtle } = require('node:crypto').webcrypto

const { MessengerClient } = require('./messenger')
const {
  generateEG,
  computeDH,
  decryptWithGCM,
  generateECDSA,
  signWithECDSA,
  HMACtoAESKey,
  bufferToString,
  cryptoKeyToJSON,
  govEncryptionDataStr
} = require('./lib')

const PORT = 3000

let caKeyPair
let govKeyPair
const clients = {}
const certificates = {}
const signatures = {}
const networkLog = [] // Stores intercepted packets for UI & Gov decryption

function bufToHex (buf) {
  return Buffer.from(buf).toString('hex')
}

async function initSystem () {
  caKeyPair = await generateECDSA()
  govKeyPair = await generateEG()

  const users = ['Alice', 'Bob', 'Claire']
  for (const u of users) {
    const client = new MessengerClient(caKeyPair.pub, govKeyPair.pub)
    const cert = await client.generateCertificate(u)
    const sig = await signWithECDSA(caKeyPair.sec, JSON.stringify(cert))
    clients[u] = client
    certificates[u] = cert
    signatures[u] = sig
  }

  // Distribute signed certificates to all clients
  for (const u of users) {
    for (const peer of users) {
      if (u !== peer) {
        await clients[u].receiveCertificate(certificates[peer], signatures[peer])
      }
    }
  }
}

async function govDecryptPacket (header, ciphertext) {
  let govKey = await computeDH(govKeyPair.sec, header.vGov)
  govKey = await HMACtoAESKey(govKey, govEncryptionDataStr)
  const mk = await decryptWithGCM(govKey, header.cGov, header.ivGov)
  const subtleMK = await subtle.importKey('raw', mk, 'AES-GCM', true, ['encrypt', 'decrypt'])
  const plaintext = await decryptWithGCM(subtleMK, ciphertext, header.receiverIV, JSON.stringify(header))
  return bufferToString(plaintext)
}

async function getRatchetSnapshot (user, peer) {
  const conn = clients[user]?.conns[peer]
  if (!conn) return { initialized: false }
  const dhsJwk = conn.DHs?.pub ? await cryptoKeyToJSON(conn.DHs.pub) : null
  const dhrJwk = conn.DHr ? await cryptoKeyToJSON(conn.DHr) : null
  return {
    initialized: true,
    Ns: conn.Ns,
    Nr: conn.Nr,
    PN: conn.PN,
    skippedKeysCount: Object.keys(conn.MKSKIPPED || {}).length,
    DHs_x: dhsJwk ? dhsJwk.x.slice(0, 16) + '...' : 'N/A',
    DHr_x: dhrJwk ? dhrJwk.x.slice(0, 16) + '...' : 'N/A'
  }
}

const server = http.createServer(async (req, res) => {
  // Serve frontend
  if (req.method === 'GET' && req.url === '/') {
    const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'))
    res.writeHead(200, { 'Content-Type': 'text/html' })
    return res.end(html)
  }

  // JSON Body parser helper
  const readBody = () => new Promise((resolve) => {
    let data = ''
    req.on('data', chunk => { data += chunk })
    req.on('end', () => resolve(data ? JSON.parse(data) : {}))
  })

  try {
    // 1. Send message (optionally hold in network queue to demo out-of-order delivery)
    if (req.method === 'POST' && req.url === '/api/send') {
      const { sender, recipient, plaintext, holdInNetwork } = await readBody()
      const [header, ciphertext] = await clients[sender].sendMessage(recipient, plaintext)

      const dhJwk = await cryptoKeyToJSON(header.dh)
      const packet = {
        id: networkLog.length + 1,
        timestamp: new Date().toLocaleTimeString(),
        sender,
        recipient,
        status: holdInNetwork ? 'DELAYED_IN_TRANSIT' : 'DELIVERED',
        rawTuple: [header, ciphertext],
        metadata: {
          n: header.n,
          pn: header.pn,
          dhPubPreview: dhJwk.x.slice(0, 18) + '...',
          receiverIV: bufToHex(header.receiverIV),
          ivGov: bufToHex(header.ivGov),
          cGovHex: bufToHex(header.cGov).slice(0, 32) + '...',
          ciphertextHex: bufToHex(ciphertext)
        },
        deliveredPlaintext: null
      }

      if (!holdInNetwork) {
        packet.deliveredPlaintext = await clients[recipient].receiveMessage(sender, [header, ciphertext])
      }

      networkLog.push(packet)
      res.writeHead(200, { 'Content-Type': 'application/json' })
      return res.end(JSON.stringify({ ok: true, packetId: packet.id }))
    }

    // 2. Deliver a previously delayed packet (Extra Credit demo)
    if (req.method === 'POST' && req.url === '/api/deliver') {
      const { packetId } = await readBody()
      const packet = networkLog.find(p => p.id === packetId)
      if (!packet) throw new Error('Packet not found')
      if (packet.status === 'DELIVERED') throw new Error('Replay detected: Packet already delivered!')

      packet.deliveredPlaintext = await clients[packet.recipient].receiveMessage(packet.sender, packet.rawTuple)
      packet.status = 'DELIVERED'

      res.writeHead(200, { 'Content-Type': 'application/json' })
      return res.end(JSON.stringify({ ok: true, plaintext: packet.deliveredPlaintext }))
    }

    // 3. Simulate tampering attack (modifies ciphertext byte and verifies rejection)
    if (req.method === 'POST' && req.url === '/api/tamper') {
      const { packetId } = await readBody()
      const packet = networkLog.find(p => p.id === packetId)
      if (!packet) throw new Error('Packet not found')

      const [header, ciphertext] = packet.rawTuple
      const tampered = new Uint8Array(ciphertext.slice(0))
      tampered[0] ^= 0xff // Flip bits in ciphertext

      await clients[packet.recipient].receiveMessage(packet.sender, [header, tampered.buffer])
      res.writeHead(200, { 'Content-Type': 'application/json' })
      return res.end(JSON.stringify({ ok: true }))
    }

    // 4. Government surveillance wiretap decryption
    if (req.method === 'POST' && req.url === '/api/gov-decrypt') {
      const { packetId } = await readBody()
      const packet = networkLog.find(p => p.id === packetId)
      if (!packet) throw new Error('Packet not found')

      const decrypted = await govDecryptPacket(packet.rawTuple[0], packet.rawTuple[1])
      res.writeHead(200, { 'Content-Type': 'application/json' })
      return res.end(JSON.stringify({ ok: true, decrypted }))
    }

    // 5. Fetch current UI state & ratchet internals
    if (req.method === 'GET' && req.url === '/api/state') {
      const sanitizedLogs = networkLog.map(({ rawTuple, ...rest }) => rest)
      const ratchets = {
        'Alice->Bob': await getRatchetSnapshot('Alice', 'Bob'),
        'Bob->Alice': await getRatchetSnapshot('Bob', 'Alice'),
        'Alice->Claire': await getRatchetSnapshot('Alice', 'Claire'),
        'Claire->Alice': await getRatchetSnapshot('Claire', 'Alice')
      }
      res.writeHead(200, { 'Content-Type': 'application/json' })
      return res.end(JSON.stringify({ logs: sanitizedLogs, ratchets }))
    }

    // 6. Reset demo session
    if (req.method === 'POST' && req.url === '/api/reset') {
      networkLog.length = 0
      await initSystem()
      res.writeHead(200, { 'Content-Type': 'application/json' })
      return res.end(JSON.stringify({ ok: true }))
    }
  } catch (err) {
    res.writeHead(400, { 'Content-Type': 'application/json' })
    return res.end(JSON.stringify({ ok: false, error: err.message || String(err) }))
  }
})

initSystem().then(() => {
  server.listen(PORT, () => {
    console.log(`Double Ratchet Demo running at http://localhost:${PORT}`)
  })
})