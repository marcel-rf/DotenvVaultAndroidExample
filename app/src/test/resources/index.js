function encrypt(key, message) {
  // set up key and nonce
  key = _decodeKey(key)
  let nonce = _generateNonce()

  // set up cipher
  let cipher = crypto.createCipheriv('aes-256-gcm', key, nonce)

  // generate ciphertext
  let ciphertext = ''
  ciphertext += cipher.update(message, 'utf8', 'hex')
  ciphertext += cipher.final('hex')
  ciphertext += cipher.getAuthTag().toString('hex')

  // prepend nonce
  ciphertext = nonce.toString('hex') + ciphertext

  // base64 encode output
  return Buffer.from(ciphertext, 'hex').toString('base64')
}

function decrypt(key, ciphertext) {
  // setup key
  key = _decodeKey(key)

  // base64 decode input
  ciphertext = Buffer.from(ciphertext, 'base64')

  // extract nonce
  const nonce = ciphertext.slice(0, 12)

  // extract authtag
  const authTag = ciphertext.slice(-16)

  // extract ciphertext
  ciphertext = ciphertext.slice(12, -16)

  // set up cipher
  const cipher = crypto.createDecipheriv('aes-256-gcm', key, nonce)
  cipher.setAuthTag(authTag)

  let message = ''
  message += cipher.update(ciphertext)
  message += cipher.final()

  return message
}