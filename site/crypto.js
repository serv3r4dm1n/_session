(function (root) {
  'use strict';

  const encoder = new TextEncoder();
  const decoder = new TextDecoder('utf-8', { fatal: true });

  function fromBase64(value) {
    const raw = atob(value);
    return Uint8Array.from(raw, (character) => character.charCodeAt(0));
  }

  function toBase64(bytes) {
    let binary = '';
    for (const value of bytes) binary += String.fromCharCode(value);
    return btoa(binary);
  }

  function fromBase64Url(value) {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    return fromBase64(normalized + '='.repeat(-normalized.length % 4));
  }

  function toBase64Url(bytes) {
    return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function concatBytes(...arrays) {
    const length = arrays.reduce((total, item) => total + item.length, 0);
    const result = new Uint8Array(length);
    let offset = 0;
    for (const item of arrays) {
      result.set(item, offset);
      offset += item.length;
    }
    return result;
  }

  async function deriveKey(password, saltBase64, iterations) {
    const material = await crypto.subtle.importKey(
      'raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits'],
    );
    const bits = await crypto.subtle.deriveBits({
      name: 'PBKDF2', hash: 'SHA-256', salt: fromBase64(saltBase64), iterations,
    }, material, 512);
    return new Uint8Array(bits);
  }

  async function openSealed(key, payload, domain, expectedFormat) {
    if (!payload || payload.format !== expectedFormat || payload.version !== 1) {
      throw new Error('Unsupported sealed payload.');
    }
    const iv = fromBase64(payload.iv || '');
    const ciphertext = fromBase64(payload.ciphertext || '');
    const tag = fromBase64(payload.tag || '');
    if (iv.length !== 16 || !ciphertext.length || ciphertext.length % 16 || tag.length !== 32) {
      throw new Error('Sealed payload is malformed.');
    }
    if (!key || key.length !== 64) throw new Error('Session key is malformed.');

    const macKey = await crypto.subtle.importKey(
      'raw', key.slice(32, 64), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'],
    );
    const authenticated = await crypto.subtle.verify(
      'HMAC', macKey, tag, concatBytes(encoder.encode(domain), iv, ciphertext),
    );
    if (!authenticated) throw new Error('Incorrect passphrase or modified data.');

    const aesKey = await crypto.subtle.importKey(
      'raw', key.slice(0, 32), { name: 'AES-CBC' }, false, ['decrypt'],
    );
    const clear = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, aesKey, ciphertext);
    return new Uint8Array(clear);
  }

  async function importRsaPublicKey(publicKeyBase64) {
    if (typeof publicKeyBase64 !== 'string' || !publicKeyBase64) {
      throw new Error('Session key is missing.');
    }
    return crypto.subtle.importKey(
      'spki', fromBase64(publicKeyBase64),
      { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt'],
    );
  }

  async function rsaEncrypt(publicKeyBase64, plaintext) {
    const publicKey = await importRsaPublicKey(publicKeyBase64);
    const ciphertext = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, plaintext);
    return new Uint8Array(ciphertext);
  }

  function randomHex(bytes) {
    return Array.from(crypto.getRandomValues(new Uint8Array(bytes)))
      .map((value) => value.toString(16).padStart(2, '0'))
      .join('');
  }

  root.SessionCrypto = {
    fromBase64,
    toBase64,
    fromBase64Url,
    toBase64Url,
    concatBytes,
    deriveKey,
    openSealed,
    validatePublicKey: importRsaPublicKey,
    rsaEncrypt,
    randomHex,
    utf8Encode: (value) => encoder.encode(value),
    utf8Decode: (value) => decoder.decode(value),
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
