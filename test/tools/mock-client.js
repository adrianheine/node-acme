'use strict';

const Jose = require('../../lib/jose');

class MockClient {
  key() {
    const jose = new Jose();
    if (this._key) {
      return Promise.resolve(this._key);
    }
    return jose.newkey()
      .then(k => {
        this._key = k;
        return k;
      });
  }

  makeJWS(nonce, url, payload, acmeVersion = 'ietf-draft') {
    const jose = new Jose(acmeVersion);
    return this.key()
      .then(k => jose.sign(k, payload, {
        nonce: nonce,
        url:   url
      }));
  }
};

module.exports = MockClient;
