let customAlphabet = null
if (typeof window === 'undefined') {
  customAlphabet = require('nanoid').customAlphabet
} else {
  customAlphabet = require('nanoid/index.browser').customAlphabet
}

module.exports = {
  ceCreateSignedRequest: ({ clientKey, secret, payload }) => {
  // *********************************
  // avoid scoping collisions
    const ceObjectHash = require('object-hash')
    const ceCopy = (src) => (JSON.parse(JSON.stringify(src)))

    const ceGenerateNonce = () => {
      const createNanoId = customAlphabet('23456789ABCDEFGHJKLMNPQRSTUVWXYZ', 16)
      const id = createNanoId()
      return id.substring(0, 4) + '-' + id.substring(4, 8) + '-' + id.substring(8, 12) + '-' + id.substring(12, 16)
    }
    // *********************************

    const requestEnvelope = {
      signatureValidator: 'external-v1',
      timestamp: Date.now(),
      nonce: ceGenerateNonce(),
      clientKey,
      payload
    }

    const request = ceCopy(requestEnvelope)
    request.secret = secret
    request.signature = ceObjectHash(request)
    return request
  }
}
