// Códigos de verificación TOTP (RFC 6238) con los parámetros que leen las seis aplicaciones del
// material: HMAC-SHA-1, 6 dígitos, intervalos de 30 s (referencia-2fa.md §8).
// SHA-1 y HMAC van en JavaScript puro, sin crypto.subtle, para que el portal funcione igual desde
// GitHub Pages, desde un archivo local y en Node (pruebas: node practica/pruebas-totp.js).
(function (raiz) {
  'use strict';

  var ALFABETO_BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  var PERIODO = 30;
  var DIGITOS = 6;

  function sha1(bytes) {
    var h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
    var largo = bytes.length;
    var total = ((largo + 9 + 63) >> 6) << 6;
    var m = new Uint8Array(total);
    m.set(bytes);
    m[largo] = 0x80;
    var bits = largo * 8;
    m[total - 4] = (bits >>> 24) & 0xff;
    m[total - 3] = (bits >>> 16) & 0xff;
    m[total - 2] = (bits >>> 8) & 0xff;
    m[total - 1] = bits & 0xff;
    m[total - 5] = Math.floor(bits / 0x100000000) & 0xff;

    var w = new Int32Array(80);
    for (var bloque = 0; bloque < total; bloque += 64) {
      for (var i = 0; i < 16; i++) {
        var j = bloque + i * 4;
        w[i] = (m[j] << 24) | (m[j + 1] << 16) | (m[j + 2] << 8) | m[j + 3];
      }
      for (i = 16; i < 80; i++) {
        var x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
        w[i] = (x << 1) | (x >>> 31);
      }
      var a = h0, b = h1, c = h2, d = h3, e = h4;
      for (i = 0; i < 80; i++) {
        var f, k;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
        else { f = b ^ c ^ d; k = 0xca62c1d6; }
        var t = (((a << 5) | (a >>> 27)) + f + e + k + w[i]) | 0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;
      }
      h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0; h4 = (h4 + e) | 0;
    }
    var salida = new Uint8Array(20);
    [h0, h1, h2, h3, h4].forEach(function (h, n) {
      salida[n * 4] = (h >>> 24) & 0xff;
      salida[n * 4 + 1] = (h >>> 16) & 0xff;
      salida[n * 4 + 2] = (h >>> 8) & 0xff;
      salida[n * 4 + 3] = h & 0xff;
    });
    return salida;
  }

  function hmacSha1(clave, mensaje) {
    if (clave.length > 64) clave = sha1(clave);
    var ipad = new Uint8Array(64 + mensaje.length);
    var opad = new Uint8Array(64 + 20);
    for (var i = 0; i < 64; i++) {
      var b = i < clave.length ? clave[i] : 0;
      ipad[i] = b ^ 0x36;
      opad[i] = b ^ 0x5c;
    }
    ipad.set(mensaje, 64);
    opad.set(sha1(ipad), 64);
    return sha1(opad);
  }

  function aBase32(bytes) {
    var salida = '', acumulado = 0, bits = 0;
    for (var i = 0; i < bytes.length; i++) {
      acumulado = (acumulado << 8) | bytes[i];
      bits += 8;
      while (bits >= 5) {
        salida += ALFABETO_BASE32[(acumulado >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    if (bits > 0) salida += ALFABETO_BASE32[(acumulado << (5 - bits)) & 31];
    return salida;
  }

  function deBase32(texto) {
    var limpio = texto.toUpperCase().replace(/[\s=-]/g, '');
    var bytes = [], acumulado = 0, bits = 0;
    for (var i = 0; i < limpio.length; i++) {
      var v = ALFABETO_BASE32.indexOf(limpio[i]);
      if (v < 0) throw new Error('Carácter no válido en base32: ' + limpio[i]);
      acumulado = (acumulado << 5) | v;
      bits += 5;
      if (bits >= 8) {
        bytes.push((acumulado >>> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    return new Uint8Array(bytes);
  }

  // Código HOTP para un contador (RFC 4226).
  function hotp(claveBytes, contador, digitos) {
    var mensaje = new Uint8Array(8);
    var alto = Math.floor(contador / 0x100000000), bajo = contador >>> 0;
    for (var i = 3; i >= 0; i--) { mensaje[i] = alto & 0xff; alto >>>= 8; }
    for (i = 7; i >= 4; i--) { mensaje[i] = bajo & 0xff; bajo >>>= 8; }
    var h = hmacSha1(claveBytes, mensaje);
    var o = h[19] & 0x0f;
    var n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
    var codigo = String(n % Math.pow(10, digitos));
    while (codigo.length < digitos) codigo = '0' + codigo;
    return codigo;
  }

  function intervalo(msEpoch) {
    return Math.floor(msEpoch / 1000 / PERIODO);
  }

  function codigo(claveBase32, msEpoch, digitos) {
    return hotp(deBase32(claveBase32), intervalo(msEpoch), digitos || DIGITOS);
  }

  // Busca el código entre los intervalos vecinos. Devuelve el desfase en intervalos (0, ±1, …)
  // o null. Con margen 1 se acepta un código del intervalo anterior o siguiente (reloj
  // ligeramente corrido); con un margen mayor el portal detecta un teléfono con la hora mal.
  function desfase(claveBase32, codigoEscrito, msEpoch, margen) {
    var limpio = String(codigoEscrito).replace(/\D/g, '');
    if (limpio.length !== DIGITOS) return null;
    var clave = deBase32(claveBase32);
    var actual = intervalo(msEpoch);
    if (hotp(clave, actual, DIGITOS) === limpio) return 0;
    for (var d = 1; d <= margen; d++) {
      if (hotp(clave, actual - d, DIGITOS) === limpio) return -d;
      if (hotp(clave, actual + d, DIGITOS) === limpio) return d;
    }
    return null;
  }

  function segundosRestantes(msEpoch) {
    return PERIODO - Math.floor(msEpoch / 1000) % PERIODO;
  }

  var api = {
    PERIODO: PERIODO,
    DIGITOS: DIGITOS,
    sha1: sha1,
    hmacSha1: hmacSha1,
    aBase32: aBase32,
    deBase32: deBase32,
    hotp: hotp,
    codigo: codigo,
    desfase: desfase,
    segundosRestantes: segundosRestantes
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else raiz.Totp = api;
})(this);
