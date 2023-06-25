test('cjs load signer', () => {
  const { ceCreateSignedRequest } = require('../index')

  const result = ceCreateSignedRequest({ clientKey: '11111', secret: '222222', payload: { success: true } })

  expect(result.payload.success).toEqual(true)
})
