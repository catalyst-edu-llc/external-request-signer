const cryptoJS = require('crypto-js')
const randomSeed = require('random-seed')
const ceCopy = (src) => (JSON.parse(JSON.stringify(src)))

const self = {
  objectHash: (obj) => {
    const src = JSON.stringify(obj).replaceAll(' ', '').replaceAll('"', '').replaceAll('\'', '')
    const sortedString = Array.from(src).sort().join('')
    return cryptoJS.SHA256(sortedString).toString()
  },
  ceGenerateNonce: () => {
    const getRandomArray = (size) => {
      const result = []
      for (let i = 0; i < size; i++) {
        result.push(randomSeed.create()(64))
      }
      return result
    }

    const createNanoId = (random, alphabet, size) => {
      const mask = (2 << Math.log(alphabet.length - 1) / Math.LN2) - 1
      const step = Math.ceil(1.6 * mask * size / alphabet.length)

      let id = ''
      while (true) {
        const bytes = random(step)
        for (let i = 0; i < step; i++) {
          const byte = bytes[i] & mask
          if (alphabet[byte]) {
            id += alphabet[byte]
            if (id.length === size) return id
          }
        }
      }
    }

    const id = createNanoId(getRandomArray, '23456789ABCDEFGHJKLMNPQRSTUVWXYZ', 16)
    return id.substring(0, 4) + '-' + id.substring(4, 8) + '-' + id.substring(8, 12) + '-' + id.substring(12, 16)
  },

  signRequest: ({ request, secret }) => {
    delete request.signature
    request.secret = secret
    request.signature = self.objectHash(request)
    delete request.secret
  },

  createSignedRequest: ({ clientKey, secret, payload }) => {
    // *********************************

    const requestEnvelope = {
      signatureValidator: 'external-v1-js',
      timestamp: Date.now(),
      nonce: self.ceGenerateNonce(),
      clientKey,
      payload
    }

    const request = ceCopy(requestEnvelope)
    self.signRequest({ request, secret })
    return request
  },

  validateSignedRequest: async ({ clientKey, secret, signedRequest, expiration = 20, nonceValidator }) => {
    const request = ceCopy(signedRequest)
    if (typeof secret === 'function') {
      secret = await secret(clientKey)
    }
    self.signRequest({ request, secret })
    if (request.signature !== signedRequest.signature) {
      throw new Error('SIGNATURE_MISMATCH')
    }
    if (Date.now() > (signedRequest.timestamp + expiration * 1000)) {
      throw new Error('EXPIRED_REQUEST')
    }
    if (nonceValidator) {
      await nonceValidator(signedRequest)
    }
    return signedRequest.payload
  }
}

module.exports = self
