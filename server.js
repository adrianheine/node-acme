// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const fs = require('fs');
const http = require('http');
const https = require('https');

const ACMEServer = require('./lib/acme-server');

const caKey = fs.readFileSync('./ca.key');
const caCert = fs.readFileSync('./ca.crt');

let serverConfig = {
  basePath: '/acme',
  host: '127.0.0.1',
  port: 80,
//  host:            "acme-v01.api.letsencrypt.org",
  terms: 'terms',
//  port: 443,
  authzExpirySeconds: 30 * 24 * 3600,
  // TODO: Change to pass in validation objects
  autoChallenge:      true,
  caKey: caKey,
  caCert: caCert,
  acmeVersion: 'le'
};

let server = new ACMEServer(serverConfig);

var httpServer = http.createServer(server.app);
var httpsServer = https.createServer({key: fs.readFileSync('./host.key'), cert: fs.readFileSync('./host.crt')}, server.app);

httpServer.listen(80);
httpsServer.listen(443);
