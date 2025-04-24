const crypto = require('crypto'); // Import crypto module

function base64urlEncode(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '') // Remove padding
    .replace(/\+/g, '-') // Replace '+' with '-'
    .replace(/\//g, '_'); // Replace '/' with '_'
}

function base64urlDecode(input) {
  return Buffer.from(
    input.replace(/-/g, '+').replace(/_/g, '/'), // Convert back to base64
    'base64'
  ).toString('utf-8');
}

function signJWT(payload, secret, expiresInSeconds = 3600) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const exp = Math.floor(Date.now() / 1000) + expiresInSeconds;
  const encodedHeader = base64urlEncode(JSON.stringify(header));
  const modifiedPayload = { ...payload, exp };
  const encodedPayload = base64urlEncode(JSON.stringify(modifiedPayload));
  const data = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto
    .createHmac('sha256', secret)
    .update(data)
    .digest('base64')
    .replace(/=/g, '') // Remove padding
    .replace(/\+/g, '-') // Replace '+' with '-'
    .replace(/\//g, '_'); // Replace '/' with '_'
  return `${data}.${signature}`;
}

function verifyJWT(token, secret) {
  try {
    const [encodedHeader, encodedPayload, signature] = token.split('.');
    const data = `${encodedHeader}.${encodedPayload}`;
    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(data)
      .digest('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');

    if (signature !== expectedSignature) {
      throw new Error('Invalid signature');
    }
    const decodedPayload = JSON.parse(base64urlDecode(encodedPayload));
    const currentTime = Math.floor(Date.now() / 1000);

    if (decodedPayload.exp && decodedPayload.exp < currentTime) {
      throw new Error('Token has expired');
    }

    return decodedPayload;
  } catch (err) {
    console.error('JWT verification failed:', err.message);
    return null;
  }
}

module.exports = {
  signJWT,
  verifyJWT,
};