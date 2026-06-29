const cryptoJS = require('crypto-js')
const randomSeed = require('random-seed')
const ceCopy = (src) => (JSON.parse(JSON.stringify(src)))

/**
 * @typedef {object} SignedRequestEnvelope
 * @property {string} signatureValidator - The version identifier of the signature validator (e.g. 'external-v1-js').
 * @property {number} timestamp - The milliseconds timestamp when the request was signed.
 * @property {string} nonce - A unique nonce for the request.
 * @property {string} clientKey - The client key identifier.
 * @property {object} payload - The arbitrary payload being transmitted.
 * @property {string} signature - The calculated hash signature for the envelope.
 */

const self = {
  /**
   * Generates a deterministic SHA-256 hash of an object.
   * Normalizes the JSON-serialized string by stripping spaces and quotes,
   * then sorting the characters.
   *
   * @function objectHash
   * @param {object} obj - The object to hash.
   * @returns {string} The calculated SHA-256 hash string.
   *
   * @example
   * const hash = objectHash({ a: 1, b: 2 });
   */
  objectHash: (obj) => {
    const src = JSON.stringify(obj).replaceAll(' ', '').replaceAll('"', '').replaceAll('\'', '')
    const sortedString = Array.from(src).sort().join('')
    return cryptoJS.SHA256(sortedString).toString()
  },

  /**
   * Generates a random request nonce string formatted as four groups of four characters separated by hyphens.
   * Uses a custom alphabet (excluding ambiguous characters) and a seeded random number generator.
   *
   * @function ceGenerateNonce
   * @returns {string} The generated nonce string (e.g. 'ABCD-EFGH-IJKL-MNOP').
   *
   * @example
   * const nonce = ceGenerateNonce();
   */
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

  /**
   * Signs a request object in place by calculating its hash signature.
   * Modifies the request object directly by injecting a `signature` property.
   *
   * @function signRequest
   * @param {object} request - Function arguments object.
   * @param {object} request.request - The request object to sign.
   * @param {string} request.secret - The secret key used for generating the signature.
   * @returns {void}
   *
   * @example
   * const request = { nonce: '123', payload: { data: 'test' } };
   * signRequest({ request, secret: 'my-secret' });
   * // request.signature is now set
   */
  signRequest: ({ request, secret }) => {
    delete request.signature
    request.secret = secret
    request.signature = self.objectHash(request)
    delete request.secret
  },

  /**
   * Creates and signs a new request envelope with a generated nonce and current timestamp.
   *
   * @function createSignedRequest
   * @param {object} clientKey - Function arguments object.
   * @param {string} clientKey.clientKey - The client identifier key.
   * @param {string} clientKey.secret - The secret key used to sign the request.
   * @param {object} clientKey.payload - The data payload to include in the request.
   * @returns {SignedRequestEnvelope} The fully signed request envelope.
   *
   * @example
   * const request = createSignedRequest({
   *   clientKey: 'client-abc',
   *   secret: 'my-secret',
   *   payload: { foo: 'bar' }
   * });
   */
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

  /**
   * Validates a signed request envelope, verifying its signature, timestamp, and optional nonce.
   *
   * @async
   * @function validateSignedRequest
   * @param {object} clientKey - Function arguments object.
   * @param {string} clientKey.clientKey - The client identifier key.
   * @param {string|Function} clientKey.secret - The secret key or an async function/callback that retrieves the secret key by clientKey.
   * @param {SignedRequestEnvelope} clientKey.signedRequest - The signed request envelope to validate.
   * @param {number} [clientKey.expiration=20] - Expiration threshold in seconds.
   * @param {Function} [clientKey.nonceValidator] - Optional async callback function to validate the nonce.
   * @returns {Promise<object>} The payload of the validated request if validation succeeds.
   * @throws {Error} Throws 'SIGNATURE_MISMATCH' if the signatures do not match.
   * @throws {Error} Throws 'EXPIRED_REQUEST' if the request has expired.
   *
   * @example
   * const payload = await validateSignedRequest({
   *   clientKey: 'client-abc',
   *   secret: 'my-secret',
   *   signedRequest,
   *   expiration: 30
   * });
   */
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
