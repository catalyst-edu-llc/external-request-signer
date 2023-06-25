let customAlphabet = null
if (typeof window === 'undefined') {
  customAlphabet = require('nanoid').customAlphabet
} else {
  customAlphabet = require('nanoid/index.browser').customAlphabet
}

const ceCopy = (src) => (JSON.parse(JSON.stringify(src)))
const objectHash = require('object-hash')

const self = {
  signRequest: ({ request, secret }) => {
    delete request.signature
    request.secret = secret
    request.signature = objectHash(request)
    delete request.secret
  },

  createSignedRequest: ({ clientKey, secret, payload }) => {
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
