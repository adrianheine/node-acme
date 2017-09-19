'use strict';

let jose = require('node-jose');

// Implements ACME's additional requirements on JWS
// https://ietf-wg-acme.github.io/acme/#request-authentication

class ACMEJose {
  constructor(acmeVersion = 'ietf-draft') {
    this.acmeVersion = acmeVersion;
  }

  newkey() {
    return this.acmeVersion == 'le' ? jose.JWK.createKeyStore().generate('RSA', '2048')
      : jose.JWK.createKeyStore().generate('EC', 'P-256');
  }

  sign(key, obj, header) {
    header.jwk = key.toJSON();

    if (!header.nonce) {
      throw new Error('Header must provide nonce');
    }

    if (this.acmeVersion != 'le' && !header.url) {
      throw new Error('Header must provide url');
    }

    let payload = JSON.stringify(obj);
    let opts = {
      format: 'flattened',
      fields: header
    };
    return jose.JWS.createSign(opts, key)
      .update(payload)
      .final();
  }

  verify(jws) {
    return new Promise((res, rej) => {
      if (!jws.protected || !jws.payload || !jws.signature) {
        rej(new Error('Non-flattened JWS'));
        return;
      }

      let header = {};
      let headerBytes = jose.util.base64url.decode(jws.protected);
      let headerJSON = jose.util.utf8.encode(headerBytes);
      header = JSON.parse(headerJSON);

      if (!header.alg || !header.jwk || !header.nonce) {
        rej(new Error('Missing field in protected header'));
        return;
      }

      if (this.acmeVersion != 'le' && !header.url) {
        rej(new Error('Header must provide url'));
        return;
      }

      res(jose.JWK.asKey(header.jwk));
    })
    .then(key => {
      if (this.acmeVersion == 'le' && key.length < 2048) {
        throw new Error('key too small');
      }
      return key;
    })
    .then(key2 => jose.JWS.createVerify(key2).verify(jws))
    .then(result => {
      result.payload = JSON.parse(result.payload);
      return result;
    });
    // TODO: Groom the return value?
  }
};

module.exports = ACMEJose;
