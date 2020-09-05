'use strict';

const uuid = require('node-uuid');
const pki = require('./pki');
const TransportServer = require('./transport-server');

const DIRECTORY_TEMPLATE = {
  'directory': '/directory',
  'newAccount':   '/new-acct',
  'newOrder':  '/new-app',
  'newReg':  '/new-cert',
  'newAuthz': '/new-authz',
  'newNonce': '/new-nonce',
};

// * Class per object type
// * Each object has static type() method
// * Each object has an ID field.
//  * For registrations, this is thumbprint of the acct key
// * Format of URLs is $BASE/$TYPE/$ID

function select(obj, fields) {
  let out = {};
  for (let field of fields) {
    if (obj[field]) {
      out[field] = obj[field];
    }
  }
  return out;
}

class Registration {
  constructor(id, jwk, contact) {
    this.id = id;
    this.status = 'good';
    this.key = jwk;
    this.contact = contact;
  }

  type() {
    return Registration.type;
  }

  marshal() {
    return select(this, Registration.publicFields);
  }
}

Registration.type = 'reg';
Registration.publicFields = [
  'key',
  'status',
  'contact',
  'agreement'
];

class Application {
  constructor(server, thumbprint) {
    this.server = server;
    this.id = uuid.v4();
    this.status = 'pending';
    this.url = server.makeURL(this);
    this.thumbprint = thumbprint;
    this.requirements = [];
  }

  type() {
    return Application.type;
  }

  markAsReady() {
    if (this.status == 'pending') {
      let unfulfilled = this.requirements.filter(req => (req.status !== 'valid'));
      if (unfulfilled.length === 0) {
        this.status = 'ready';
      }
    }
  }

  marshal() {
    this.authorizations = this.requirements.map(r => r.url)
    this.finalize = this.url + '/finalize'
    return select(this, Application.publicFields);
  }
}

Application.type = 'app';
Application.publicFields = [
  'status',
  'expires',
  'notBefore',
  'notAfter',
  'requirements',
  'authorizations',
  'certificate',
  'finalize',
];

class Authorization {
  constructor(server, thumbprint, name, scope) {
    this.id = uuid.v4();
    this.status = 'pending';
    this.url = server.makeURL(this);
    this.thumbprint = thumbprint;
    this.identifier = {
      type:  'dns',
      value: name
    };
    this.scope = scope;

    let offset = server.policy.authzExpirySeconds * 1000;
    let expires = new Date();
    expires.setTime(expires.getTime() + offset);
    this.expires = expires;

    this.challengeObj = [];
    if (server.policy.challenges.http) {
      // TODO add an HTTP challenge
    }
    if (server.policy.challenges.dns) {
      // TODO add a DNS challenge
    }
    if (server.policy.challenges.tlssni) {
      // TODO add a TLS-SNI challenge
    }
    if (server.policy.challenges.auto) {
      // XXX: Non-spec; this challenge auto-completes whenever it gets a POST,
      // with no validation.  Useful mainly for testing.
      // XXX: This should get factored out into its own thing, for parallelism.
      this.challengeObj.push({
        type:   'auto',
        status: 'pending',
        update: function() { this.status = 'valid'; return Promise.resolve(); },
        toJSON: function() { return {type: this.type, status: this.status}; }
      });
    }
    this.update();
  }

  update() {
    this.challenges = this.challengeObj.map((x, i) => {
      let obj = x.toJSON();
      obj.url = this.url + '/' + i.toString();
      return obj;
    });

    let now = new Date();
    let validChallenges = this.challenges.filter(x => (x.status === 'valid'));
    if (this.expires < now) {
      this.status = 'invalid';
    } else if (validChallenges.length > 0) {
      this.status = 'valid';
    }
  }

  type() {
    return Authorization.type;
  }

  marshal() {
    this.update();
    return select(this, Authorization.publicFields);
  }

  asRequirement() {
    return {
      type:   'authorization',
      status: this.status,
      url:    this.url
    };
  }
}

Authorization.type = 'authz';
Authorization.publicFields = [
  'identifier',
  'status',
  'expires',
  'scope',
  'challenges',
  'combinations'
];

class Certificate {
  constructor(server) {
    this.id = uuid.v4();
    this.url = server.makeURL(this);
  }

  type() {
    return Certificate.type;
  }

  marshal() {
    return this.body;
  }
}

Certificate.type = 'cert';

class DB {
  constructor() {
    this.store = {};
  }

  put(obj) {
    let type = obj.type();
    if (!this.store[type]) {
      this.store[type] = {};
    }
    this.store[type][obj.id] = obj;
  }

  get(type, id) {
    if (!this.store[type]) {
      return null;
    }
    return this.store[type][id];
  }

  authzFor(thumbprint, name) {
    for (let key in this.store['authz']) {
      if (!this.store['authz'].hasOwnProperty(key)) {
        continue;
      }

      let authz = this.store['authz'][key];
      if ((authz.thumbprint === thumbprint) &&
          (authz.identifier.value === name)) {
        return authz;
      }
    }
    return null;
  }

  updateAppsFor(authz) {
    let dependencies = [];
    for (let key in this.store['app']) {
      if (!this.store['app'].hasOwnProperty(key)) {
        continue;
      }

      let app = this.store['app'][key];
      if (app.thumbprint !== authz.thumbprint) {
        continue;
      }

      app.requirements.map(req => {
        if (req.type === 'authorization' && req.url === authz.url) {
          req.status = authz.status;
        }
      });
      this.put(app);
      dependencies.push(app);
    }

    dependencies.forEach(app => app.markAsReady());
    return Promise.resolve();
  }
}

class CA {
  constructor(caKey, caCert) {
    this.caKey = caKey;
    this.caCert = caCert;
  }

  issue(/* application */) {
    // XXX: Stub
    return Promise.resolve({url: 'this-is-not-a-url'});
  }

  issueCertificate(csr, notBefore, notAfter) {
    return pki.issueCRT(csr, notBefore, notAfter, this.caCert, this.caKey);
  }
}

function problem(type, title, description) {
  return {
    type:        'urn:ietf:params:acme:error:' + type,
    title:       title,
    description: description
  };
}

class ACMEServer {
  // Options:
  // * hostname
  // * port
  // * basePath
  // * acmeVersion
  constructor(options) {
    options = options || {};
    let host = options.host || 'localhost';
    let port = options.port || 80;
    let basePath = options.basePath || '';
    this.acmeVersion = options.acmeVersion || 'ietf-draft';

    // Set policy preferences
    this.policy = {
      authzExpirySeconds:   options.authzExpirySeconds,
      maxValiditySeconds:   options.maxValiditySeconds,
      allowedExtensions:    options.allowedExtensions,
      scopedAuthorizations: options.scopedAuthorizations,
      requireOOB:           options.requireOOB,
      challenges:           {
        dns:    options.dnsChallenge,
        http:   options.httpChallenge,
        tlssni: options.tlssniChallenge,
        auto:   options.autoChallenge
      }
    };

    // Set up a CA
    this.CA = new CA(options.caKey, options.caCert);

    // Set the base URL, so we can construct others
    switch (port) {
      case 80:  this.baseURL = `http://${host}${basePath}`; break;
      case 443: this.baseURL = `https://${host}${basePath}`; break;
      default: this.baseURL = `http://${host}:${port}${basePath}`; break;
    }

    // Set up a database
    this.db = new DB();

    // Initialize the directory object
    this._directory = {'meta': {}};
    for (let name in DIRECTORY_TEMPLATE) {
      if (DIRECTORY_TEMPLATE.hasOwnProperty(name)) {
        this._directory[name] = this.baseURL + DIRECTORY_TEMPLATE[name];
      }
    }
    this.terms = options.terms;

    // Create a transport-level server
    this.transport = new TransportServer(this.acmeVersion, url => {
      const id = url.match(/http:\/\/acme-v02.api.letsencrypt.org\/acme\/reg\/(\w+)$/)[1]
      return this.db.get(Registration.type, id).key
    });
    this.app.get(basePath + '/:type/:id', (req, res) => this.fetch(req, res));
    this.app.get(basePath + '/authz/:id/:index', (req, res) => this.fetchChallenge(req, res));
    this.app.get(DIRECTORY_TEMPLATE['directory'], (req, res) => this.directory(req, res));
    this.app.post(basePath + DIRECTORY_TEMPLATE['newAccount'], (req, res) => this.newReg(req, res));
    this.app.post(basePath + '/reg/:id', (req, res) => this.updateReg(req, res));
    this.app.post(basePath + DIRECTORY_TEMPLATE['newOrder'], (req, res) => this.newApp(req, res));
    this.app.post(basePath + '/app/:id/finalize', (req, res) => this.finalizeOrder(req, res))
    this.app.post(basePath + '/app/:id', (req, res) => this.getOrder(req, res))
    this.app.post(basePath + '/authz/:id', (req, res) => this.getAuthz(req, res));
    this.app.post(basePath + '/authz/:id/:index', (req, res) => this.updateAuthz(req, res));
    this.app.post(basePath + '/cert/:id', (req, res) => this.getCert(req, res));
    this.app.head(basePath + DIRECTORY_TEMPLATE['newNonce'], (req, res) => this.newNonce(req, res));
    this.app.get(basePath + DIRECTORY_TEMPLATE['newNonce'], (req, res) => this.newNonce(req, res));
    // TODO others
  }

  newNonce(req, res) {
    const isGet = req.method == "GET"
    res.status(isGet ? 204 : 200)
    res.setHeader("Cache-Control", "no-store")
    res.send()
  }

  getAuthz(req, res) {
    let thumbprint = req.accountKeyThumbprint;
    let reg = this.db.get(Registration.type, thumbprint);
    if (!reg) {
      res.status(401);
      res.send(problem('unauthorized', 'Unknown account key'));
      return;
    }
    let authz = this.db.get(Authorization.type, req.params.id);
    res.status(201);
    res.send({status: authz.status, identifier: authz.identifier, challenges: [{type: 'http-01', token: 'token', url: authz.url + '/0' }]});
  }

  get app() {
    return this.transport.app;
  }

  get terms() {
    return this._directory.meta['terms-of-service'];
  }

  set terms(url) {
    this._directory.meta['terms-of-service'] = url;
  }

  // GET request handlers

  directory(req, res) {
    res.json(this._directory);
  }

  fetch(req, res) {
    let type = req.params.type;
    let id = req.params.id;

    // Attempt to fetch
    let status = 200;
    let body = this.db.get(type, id);
    if (body) {
      body = body.marshal();
    }

    // Overwrite with errors if necessary
    if (type === Registration.type) {
      status = 401;
      body = problem('unauthorized', 'GET requests not allowed for registrations');
    } else if (!body) {
      status = 404;
      body = '';
    }

    res.status(status);
    res.send(body);
    res.end();
  }

  fetchChallenge(req, res) {
    let authz = this.db.get(Authorization.type, req.params.id);
    let index = parseInt(req.params.index);
    if (!authz || isNaN(index) || !(index in authz.challenges)) {
      res.status(404);
      res.end();
      return;
    }

    authz.update();
    this.db.put(authz);

    authz.challenges[0].status = 'valid';
    res.status(200);
    res.send(authz.challenges[index]);
  }

  // POST request handlers

  makeURL(obj) {
    let type = obj.type();
    let id = obj.id;
    return `${this.baseURL}/${type}/${id}`;
  }

  newReg(req, res) {
    let jwk = req.accountKey;
    let contact = req.payload.contact;
    let thumbprint = req.accountKeyThumbprint;

    // Check for existing registrations
    let existing = this.db.get(Registration.type, thumbprint);
    if (existing) {
      res.status(200);
      res.set('location', this.makeURL(existing));
      res.end();
      return;
    }

    // Store a new registration
    let reg = new Registration(thumbprint, jwk, contact);
    this.db.put(reg);
    res.status(201);
    res.set('location', this.makeURL(reg));
    if (this.terms) {
      res.links({'terms-of-service': this.terms});
    }
    res.send(reg.marshal());
  }

  updateReg(req, res) {
    // Check that account key is registered
    let thumbprint = req.accountKeyThumbprint;
    let reg = this.db.get(Registration.type, thumbprint);
    if (!reg) {
      res.status(401);
      res.send(problem('unauthorized', 'Unknown account key'));
      return;
    }
    if (req.params.id !== thumbprint) {
      res.status(401);
      res.send(problem('unauthorized', 'Unauthorized account key'));
      return;
    }

    if (req.payload.contact) {
      reg.contact = req.payload.contact;
    }
    if (req.payload.agreement) {
      if (req.payload.agreement !== this.terms) {
        res.status(400);
        res.send(problem('malformed', 'Incorrect agreement URL'));
        return;
      }
      reg.agreement = req.payload.agreement;
    }
    this.db.put(reg);

    res.status(200);
    if (this.terms) {
      res.links({'terms-of-service': this.terms});
    }
    res.send(reg.marshal());
  }

  newApp(req, res) {
    // Check that account key is registered
    let thumbprint = req.accountKeyThumbprint;
    let reg = this.db.get(Registration.type, thumbprint);
    if (!reg) {
      res.status(401);
      res.send(problem('unauthorized', 'Unknown account key'));
      return;
    }

    // Create a stub application
    let app = new Application(this, thumbprint);
    let scope = (this.policy.scopedAuthorizations)? app.url : undefined;

    // Parse the request elements, determine if it's acceptable
    let names;
    try {
      names = req.payload.identifiers.map(x => x.value);

      if (req.payload.notBefore) {
        let notBefore = new Date(req.payload.notBefore);
        if (isNaN(notBefore.getTime())) {
          throw new Error('Invalid notBefore format');
        }
        app.notBefore = req.payload.notBefore;
      }

      if (req.payload.notAfter) {
        let notAfter = new Date(req.payload.notAfter);
        if (isNaN(notAfter.getTime())) {
          throw new Error('Invalid notAfter format');
        }
        app.notAfter = req.payload.notAfter;
      }
    } catch (e) {
      res.status(400);
      res.send(problem('malformed', 'Invalid new application', e.message));
      return;
    }

    // Assemble authorization requirements
    for (let name of names) {
      let authz = this.db.authzFor(thumbprint, name);
      if (!authz) {
        authz = new Authorization(this, thumbprint, name, scope);
      }
      this.db.put(authz);
      app.requirements.push(authz.asRequirement());
    }

    // TODO: Set OOB if required by policy

    // Return the application
    this.db.put(app);
    res.status(201);
    res.set('location', app.url);
    res.send(app.marshal());
  }

  getCert(req, res) {
    // Check that account key is registered
    let thumbprint = req.accountKeyThumbprint;
    let reg = this.db.get(Registration.type, thumbprint);
    if (!reg) {
      res.status(401);
      res.send(problem('unauthorized', 'Unknown account key'));
      return;
    }

    let cert = this.db.get(Certificate.type, req.params.id);
    if (!cert) {
      res.status(404);
      return
    }
    res.send(cert.marshal())
  }

  finalizeOrder(req, res) {
    // Check that account key is registered
    let thumbprint = req.accountKeyThumbprint;
    let reg = this.db.get(Registration.type, thumbprint);
    if (!reg) {
      res.status(401);
      res.send(problem('unauthorized', 'Unknown account key'));
      return;
    }

    let order = this.db.get(Application.type, req.params.id);
    if (!order) {
      res.status(404);
      return
    }

    order.status = "processing"
    // Create a stub application
    let cert = new Certificate(this);
    let scope = (this.policy.scopedAuthorizations)? cert.url : undefined;

    // Parse the request elements, determine if it's acceptable
    let names, csr, notBefore, notAfter;
    try {
      if (!req.payload.csr) {
        throw new Error('CSR must be provided');
      }

      let _csr = pki.checkCSR(req.payload.csr, this.policy);
      if (_csr.error) {
        throw new Error(_csr.error);
      }
      names = _csr.names;
      csr = req.payload.csr;
    } catch (e) {
      res.status(400);
      res.send(problem('malformed', 'Invalid new certificate request', e.message));
      order.status = "ready"
      return;
    }

    notBefore = order.notBefore || new Date();
    notAfter = order.notAfter;
    if (!notAfter) {
      notAfter = new Date();
      notAfter.setFullYear((new Date()).getFullYear() + 1);
    }

    // Assemble authorization requirements
    for (let name of names) {
      let authz = this.db.authzFor(thumbprint, name);
      if (!authz) {
        authz = new Authorization(this, thumbprint, name, scope);
      }
      this.db.put(authz);
  //    app.requirements.push(authz.asRequirement());
    }

    // TODO: Set OOB if required by policy

    cert.body = this.CA.issueCertificate(csr, notBefore, notAfter);
    order.status = "valid"
    order.certificate = cert.url
    // Return the application
    this.db.put(cert);
    res.status(201);
    res.set('location', order.url);
    res.send(order.marshal());
  }

  getOrder(req, res) {
    let order = this.db.get(Application.type, req.params.id);
    if (!order) {
      res.status(404);
      return
    }
    res.status(200);
    res.send(order.marshal());
  }

  updateAuthz(req, res) {
    // Check that the requested authorization and challenge exist
    let authz = this.db.get(Authorization.type, req.params.id);
    let index = parseInt(req.params.index);
    if (!authz || isNaN(index) || !(index in authz.challenges)) {
      res.status(404);
      res.end();
      return;
    }

    // Check that account key is registered and appropriate
    let thumbprint = req.accountKeyThumbprint;
    let reg = this.db.get(Registration.type, thumbprint);
    if (!reg) {
      res.status(401);
      res.send(problem('unauthorized', 'Unknown account key'));
      res.end();
      return;
    }
    if (reg.id !== authz.thumbprint) {
      res.status(401);
      res.send(problem('unauthorized', 'Unauthorized account key'));
      res.end();
      return;
    }

    // Asynchronously update the challenge, the authorization, and any
    // applications that depend on the authorization.
    //
    // NB: It's nice for testing to have the response only go back after
    // everything is updated, since then you know that anything that's going to
    // be issued has been.  However, updates are slow, so we might want to go
    // async ultimately.
    authz.challengeObj[index].update(res.payload)
      .then(() => {
        authz.update();
      })
      .then(() => {
        this.db.updateAppsFor(authz);
      })
      .then(() => {
        res.status(200);
        res.send(authz.challenges[index]);
        res.end();
      });
  }
}

module.exports = ACMEServer;
