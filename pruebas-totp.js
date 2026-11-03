// Pruebas de totp.js con los vectores oficiales. Uso: node practica/pruebas-totp.js
'use strict';
var assert = require('assert');
var crypto = require('crypto');
var Totp = require('./totp.js');

function bytes(texto) { return new Uint8Array(Buffer.from(texto, 'utf8')); }
function hex(b) { return Buffer.from(b).toString('hex'); }

// SHA-1 contra la implementación de Node, con largos que cruzan los bordes de bloque.
[0, 1, 55, 56, 63, 64, 65, 119, 120, 1000].forEach(function (n) {
  var entrada = crypto.randomBytes(n);
  assert.strictEqual(hex(Totp.sha1(new Uint8Array(entrada))),
    crypto.createHash('sha1').update(entrada).digest('hex'), 'sha1 de ' + n + ' bytes');
});

// HMAC-SHA-1 (RFC 2202, caso 2) y con clave larga contra Node.
assert.strictEqual(hex(Totp.hmacSha1(bytes('Jefe'), bytes('what do ya want for nothing?'))),
  'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79');
var claveLarga = crypto.randomBytes(100), mensaje = crypto.randomBytes(40);
assert.strictEqual(hex(Totp.hmacSha1(new Uint8Array(claveLarga), new Uint8Array(mensaje))),
  crypto.createHmac('sha1', claveLarga).update(mensaje).digest('hex'));

// HOTP (RFC 4226, apéndice D).
var secreto = bytes('12345678901234567890');
['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489']
  .forEach(function (esperado, contador) {
    assert.strictEqual(Totp.hotp(secreto, contador, 6), esperado, 'HOTP contador ' + contador);
  });

// TOTP SHA-1 (RFC 6238, apéndice B, 8 dígitos).
var secretoBase32 = Totp.aBase32(secreto);
assert.strictEqual(secretoBase32, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
[[59, '94287082'], [1111111109, '07081804'], [1111111111, '14050471'],
 [1234567890, '89005924'], [2000000000, '69279037'], [20000000000, '65353130']]
  .forEach(function (caso) {
    assert.strictEqual(Totp.codigo(secretoBase32, caso[0] * 1000, 8), caso[1], 'TOTP t=' + caso[0]);
  });

// Base32 ida y vuelta, con espacios y minúsculas como las escribe una persona.
var aleatorio = new Uint8Array(crypto.randomBytes(20));
var texto = Totp.aBase32(aleatorio);
assert.strictEqual(hex(Totp.deBase32(texto.toLowerCase().replace(/(.{4})/g, '$1 '))), hex(aleatorio));

// Desfase: código actual, vecino aceptado, reloj corrido 5 minutos detectado.
var ahora = 1700000000000;
assert.strictEqual(Totp.desfase(secretoBase32, Totp.codigo(secretoBase32, ahora), ahora, 1), 0);
assert.strictEqual(Totp.desfase(secretoBase32, Totp.codigo(secretoBase32, ahora - 30000), ahora, 1), -1);
assert.strictEqual(Totp.desfase(secretoBase32, Totp.codigo(secretoBase32, ahora + 300000), ahora, 1), null);
assert.strictEqual(Totp.desfase(secretoBase32, Totp.codigo(secretoBase32, ahora + 300000), ahora, 20), 10);
assert.strictEqual(Totp.desfase(secretoBase32, '12345', ahora, 1), null);

console.log('totp.js: todas las pruebas pasaron');
