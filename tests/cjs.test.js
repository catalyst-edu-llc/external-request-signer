test('cjs load signer', () => {
  const { createSignedRequest } = require('../index')

  const result = createSignedRequest({ clientKey: '11111', secret: '222222', payload: { success: true } })

  expect(result.payload.success).toEqual(true)
})

test('signature match', async () => {
  const { createSignedRequest, validateSignedRequest } = require('../index')

  const result = createSignedRequest({ clientKey: '11111', secret: '222222', payload: { success: true } })

  const validatedPayload = await validateSignedRequest({ clientKey: '11111', secret: '222222', signedRequest: result })
  expect(validatedPayload.success).toEqual(true)
})

test('expired timestamp', async () => {
  const { setTimeout } = require('node:timers/promises')

  const { createSignedRequest, validateSignedRequest } = require('../index')

  const result = createSignedRequest({ clientKey: '11111', secret: '222222', payload: { success: true } })
  let errorMsg = null
  try {
    await setTimeout(3000)
    const validatedPayload = await validateSignedRequest({ clientKey: '11111', secret: '222222', signedRequest: result, expiration: 2 })
  } catch (ex) {
    errorMsg = ex.message
  }
  expect(errorMsg).toEqual('EXPIRED_REQUEST')
})

test('nonce failed validation', async () => {
  const { createSignedRequest, validateSignedRequest } = require('../index')

  const result = createSignedRequest({ clientKey: '11111', secret: '222222', payload: { success: true } })
  let errorMsg = null
  try {
    const validatedPayload = await validateSignedRequest({ clientKey: '11111', secret: '222222', signedRequest: result, nonceValidator: () => { throw new Error('BAD_NONCE') } })
  } catch (ex) {
    errorMsg = ex.message
  }

  expect(errorMsg).toEqual('BAD_NONCE')
})
