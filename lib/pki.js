'use strict';

const forge = require('node-forge');

let DNS_RE = /^([a-z0-9][a-z0-9-]{1,62}\.)+[a-z][a-z0-9-]{0,62}$/;

function parseCSR(base64url) {
  // Convert to normal base64
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }

  // Append PEM tags for CERTIFICATE REQUEST
  let pem = '-----BEGIN CERTIFICATE REQUEST-----\n'
          + base64 + '\n'
          + '-----END CERTIFICATE REQUEST-----\n';

  // Parse with Forge
  let csr = forge.pki.certificationRequestFromPem(pem);

  return csr;
}

function checkCSR(base64url) {
  let csr = parseCSR(base64url);

  // Set:
  // * error
  // * names
  // CSR = (version, subject, spki, attributes)

  // No elements to Subject besides CN
  let commonName;
  csr.subject.attributes.map(attr => {
    if (attr.name !== 'commonName') {
      return {error: 'Subject must have only commonName'};
    } else if (commonName) {
      return {error: 'Subject has multiple commonName values'};
    }

    commonName = attr.value.toLowerCase();
    if (!commonName.match(DNS_RE)) {
      return {error: 'Subject commonName is not a DNS name'};
    }
  });

  // Key has an acceptable algorithm / length
  // XXX: Forge doesn't really allow us to inspect this

/*
  if (csr.publicKey.n.bitLength() < 2048) {
    throw new Error("Key too small");
  }
*/

  // No attributes besides extensionRequest
  let extensions = [];
  csr.attributes.map(attr => {
    if (attr.name !== 'extensionRequest') {
      return {error: 'No attributes besides extensionRequest allowed'};
    } else if (extensions.length > 0) {
      return {error: 'Multiple extensionRequest attributes'};
    }

    extensions = attr.extensions;
  });

  // No extensions besides SAN
  let sans = [];
  extensions.map(extn => {
    if (extn.name !== 'subjectAltName') {
      return {error: 'Forbidden extension type'};
    } else if (sans.length > 0) {
      return {error: 'Multiple SAN extensions'};
    }

    sans = extn.altNames;
  });

  // No SANs besides dNSName
  // CN and all dNSNames MUST be DNS names
  let names = {};
  if (commonName) {
    names[commonName] = true;
  }
  sans.map(san => {
    if (san.type !== 2) {
      return {error: 'Non-dNSName SAN'};
    }

    let name = san.value.toLowerCase();
    if (!name.match(DNS_RE)) {
      return {error: 'dNSName SAN is not a DNS name'};
    }

    names[name] = true;
  });

  let nameList = [];
  for (let name in names) {
    if (names.hasOwnProperty(name)) {
      nameList.push(name);
    }
  }

  if (nameList.length === 0) {
    return {error: 'No names in CSR'};
  }

  return {names: nameList};
}

let nextSerialNumber = 1;

function getNextSerialNumber() {
  let ser = (nextSerialNumber++).toString(16);
  if (ser.length % 2 === 1) {
    ser = '0' + ser;
  }
  return ser;
}

function issueCRT(csr_base64url, notBefore, notAfter, caCert, privateCAKey) {
  let csr = parseCSR(csr_base64url);
  let cert = forge.pki.createCertificate();

  cert.publicKey = csr.publicKey;
  cert.setSubject(csr.subject.attributes);
  let extensions_attribute = csr.getAttribute({name: 'extensionRequest'});
  if (extensions_attribute) {
    cert.setExtensions(extensions_attribute.extensions);
  }

  cert.serialNumber = getNextSerialNumber();
  cert.validity.notBefore = notBefore;
  cert.validity.notAfter = notAfter;

  cert.setIssuer(forge.pki.certificateFromPem(caCert).subject.attributes);
  cert.sign(forge.pki.privateKeyFromPem(privateCAKey), forge.md.sha256.create());

  return new Buffer(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(), 'binary');
}

module.exports = {
  checkCSR: checkCSR,
  issueCRT: issueCRT
};
