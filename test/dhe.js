// Copyright 2015 Joyent, Inc.  All rights reserved.

var test = require('tape').test;

var sshpk = require('../lib/index');
var fs = require('fs');
var path = require('path');
var crypto = require('crypto');

var ED_KEY, ED2_KEY, EC_KEY, EC2_KEY, ECOUT_KEY, DS_KEY, DS2_KEY, DSOUT_KEY;
var C_KEY, C2_KEY;
var C_SSH;

test('setup', function (t) {
	var k = fs.readFileSync(path.join(__dirname, 'id_ed25519'));
	ED_KEY = sshpk.parsePrivateKey(k);
	k = fs.readFileSync(path.join(__dirname, 'id_ed255192'));
	ED2_KEY = sshpk.parsePrivateKey(k);
	k = fs.readFileSync(path.join(__dirname, 'id_ecdsa2'));
	EC_KEY = sshpk.parsePrivateKey(k);
	k = fs.readFileSync(path.join(__dirname, 'id_ecdsa3'));
	EC2_KEY = sshpk.parsePrivateKey(k);
	k = fs.readFileSync(path.join(__dirname, 'id_ecdsa'));
	ECOUT_KEY = sshpk.parsePrivateKey(k);
	k = fs.readFileSync(path.join(__dirname, 'id_dsa2'));
	DS_KEY = sshpk.parsePrivateKey(k);
	k = fs.readFileSync(path.join(__dirname, 'id_dsa3'));
	DS2_KEY = sshpk.parsePrivateKey(k);
	k = fs.readFileSync(path.join(__dirname, 'id_dsa'));
	DSOUT_KEY = sshpk.parsePrivateKey(k);
	t.end();
});

test('dhe shared secret', function (t) {
	var dh1 = DS_KEY.createDiffieHellman();
	var secret1 = dh1.computeSecret(DS2_KEY.toPublic());
	t.ok(Buffer.isBuffer(secret1));

	var dh2 = DS2_KEY.createDiffieHellman();
	var secret2 = dh2.computeSecret(DS_KEY.toPublic());
	t.deepEqual(secret1, secret2);
	t.end();
});

test('dhe reject diff primes', function (t) {
	var dh = DS_KEY.createDH();
	t.throws(function () {
		dh.computeSecret(DSOUT_KEY.toPublic());
	});
	t.throws(function () {
		dh.setKey(DSOUT_KEY);
	});
	dh.setKey(DS2_KEY);
	t.strictEqual(dh.getKey().fingerprint().toString(),
	    DS2_KEY.fingerprint().toString());

	var dh2 = DSOUT_KEY.createDH();
	t.throws(function () {
		dh2.setKey(DS_KEY);
	});
	t.end();
});

test('dhe generate ephemeral', function (t) {
	var dh = DS_KEY.toPublic().createDH();
	t.throws(function () {
		dh.computeSecret(DS2_KEY);
	});
	var ek = dh.generateKey();
	t.ok(ek instanceof sshpk.PrivateKey);
	t.strictEqual(ek.type, 'dsa');
	t.strictEqual(ek.size, 2048);

	var secret1 = dh.computeSecret(DS_KEY);
	var secret2 = DS_KEY.createDH().computeSecret(ek);
	t.deepEqual(secret1, secret2);
	t.end();
});

test('ecdhe shared secret', function (t) {
	var dh1 = EC_KEY.createDH();
	var secret1 = dh1.computeSecret(EC2_KEY.toPublic());
	t.ok(Buffer.isBuffer(secret1));

	var dh2 = EC2_KEY.createDH();
	var secret2 = dh2.computeSecret(EC_KEY.toPublic());
	t.deepEqual(secret1, secret2);
	t.end();
});

test('ecdhe generate ephemeral', function (t) {
	var dh = EC_KEY.createDH();
	var ek = dh.generateKey();
	t.ok(ek instanceof sshpk.PrivateKey);
	t.strictEqual(ek.type, 'ecdsa');
	t.strictEqual(ek.curve, 'nistp256');

	var secret1 = dh.computeSecret(EC_KEY);
	var secret2 = EC_KEY.createDH().computeSecret(ek);
	t.deepEqual(secret1, secret2);
	t.end();
});

test('ecdhe reject diff curves', function (t) {
	var dh = EC_KEY.createDH();
	t.throws(function () {
		dh.computeSecret(ECOUT_KEY.toPublic());
	});
	t.throws(function () {
		dh.setKey(ECOUT_KEY);
	});
	dh.setKey(EC2_KEY);
	t.strictEqual(dh.getKey().fingerprint().toString(),
	    EC2_KEY.fingerprint().toString());

	var dh2 = ECOUT_KEY.createDH();
	t.throws(function () {
		dh2.setKey(EC_KEY);
	});
	t.end();
});

test('derive ed25519 -> curve25519', function (t) {
	C_KEY = ED_KEY.derive('curve25519');
	t.strictEqual(C_KEY.type, 'curve25519');
	t.strictEqual(C_KEY.size, 256);
	C_SSH = C_KEY.toBuffer('ssh');
	C2_KEY = ED2_KEY.derive('curve25519');
	t.end();
});

test('derive curve25519 -> ed25519', function (t) {
	var k = sshpk.parsePrivateKey(C_SSH);
	t.strictEqual(k.type, 'curve25519');
	t.strictEqual(k.size, 256);
	var k2 = k.derive('ed25519');
	t.strictEqual(k2.type, 'ed25519');
	t.ok(k2.fingerprint().matches(ED_KEY));
	t.strictEqual(k2.part.r.toString('base64'),
	    ED_KEY.part.r.toString('base64'));
	t.end();
});

test('curve25519 shared secret', function (t) {
	t.throws(function () {
		ED_KEY.createDH();
	});
	var secret1 = C_KEY.createDH().computeSecret(C2_KEY.toPublic());
	var secret2 = C2_KEY.createDH().computeSecret(C_KEY);
	t.deepEqual(secret1, secret2);
	t.end();
});

test('curve25519 generate ephemeral', function (t) {
	var dh = C_KEY.toPublic().createDH();
	t.throws(function () {
		dh.computeSecret(C2_KEY.toPublic());
	});
	var ek = dh.generateKeys();
	t.ok(ek instanceof sshpk.PrivateKey);
	t.strictEqual(ek.type, 'curve25519');
	t.end();
});

test('curve25519 validation', function (t) {
	var dh = C_KEY.createDH();
	t.throws(function () {
		dh.computeSecret(EC_KEY.toPublic());
	});
	t.throws(function () {
		dh.setKey(EC_KEY);
	});
	dh.setKey(C2_KEY);
	t.strictEqual(dh.getKey().fingerprint().toString(),
	    C2_KEY.fingerprint().toString());

	var dh2 = EC_KEY.createDH();
	t.throws(function () {
		dh2.setKey(C_KEY);
	});
	t.end();
});
