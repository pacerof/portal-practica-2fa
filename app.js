// Portal de Práctica 2FA — especificación en referencia-2fa.md §8.
// Recorre el ciclo de vida de la `Cuenta` (§3.1) sin servidor: todo el estado vive en
// localStorage de este navegador. Nunca se pide una contraseña ni un correo.
(function () {
  'use strict';

  var CLAVE_ALMACEN = 'portal2fa.v1';
  var EMISOR = 'Portal de Práctica 2FA';
  var CICLO = ['SOLO_CONTRASEÑA', 'FACTOR_VERIFICADO', 'CON_RESPALDO', 'DISPOSITIVO_PERDIDO', 'RECUPERADA'];
  var CANTIDAD_RESPALDO = 8;
  var MARGEN_ACEPTADO = 1;     // ±1 intervalo de 30 s (referencia-2fa.md §8)
  var MARGEN_DIAGNOSTICO = 20; // hasta ±10 min: se reconoce un teléfono con la hora corrida

  // ---------------------------------------------------------------- estado

  function estadoInicial() {
    return {
      version: 1,
      nombre: null,
      cuenta: 'SOLO_CONTRASEÑA',
      factores: [],              // { id, clave, etiqueta, creado, estado: PENDIENTE | ACTIVO | REVOCADO }
      respaldo: [],              // { codigo, usado }
      respaldoConfirmado: false,
      sesion: false,
      ingresoConCodigo: false,
      recuperada: false,
      escenarios: {},            // id → índice original elegido
      ordenEscenarios: {},       // id → orden en que se muestran las opciones
      autodeclaradas: {},        // casillas que marca el estudiante en el resumen
      historial: []
    };
  }

  var almacenOk = true;
  function cargar() {
    try {
      var texto = window.localStorage.getItem(CLAVE_ALMACEN);
      if (texto) {
        var leido = JSON.parse(texto);
        if (leido && leido.version === 1) return Object.assign(estadoInicial(), leido);
      }
    } catch (e) { almacenOk = false; }
    return estadoInicial();
  }
  function guardar() {
    try { window.localStorage.setItem(CLAVE_ALMACEN, JSON.stringify(estado)); }
    catch (e) { almacenOk = false; }
  }
  var estado = cargar();

  function registrar(texto) {
    estado.historial.unshift({ t: Date.now(), texto: texto });
    estado.historial = estado.historial.slice(0, 30);
  }

  function factoresEn(est) { return estado.factores.filter(function (f) { return f.estado === est; }); }
  function factorPendiente() { return factoresEn('PENDIENTE')[0] || null; }
  function respaldoDisponible() { return estado.respaldo.filter(function (c) { return !c.usado; }); }
  function perdido() { return estado.cuenta === 'DISPOSITIVO_PERDIDO'; }

  // ---------------------------------------------------------------- utilidades

  function esc(texto) {
    return String(texto).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function aleatorio(n) {
    var b = new Uint8Array(n);
    window.crypto.getRandomValues(b);
    return b;
  }

  function claveNueva() { return Totp.aBase32(aleatorio(20)); }
  function agrupar(clave) { return clave.replace(/(.{4})/g, '$1 ').trim(); }

  function codigosRespaldoNuevos() {
    var codigos = [];
    while (codigos.length < CANTIDAD_RESPALDO) {
      var b = aleatorio(4);
      var n = ((b[0] << 24) >>> 0) + (b[1] << 16) + (b[2] << 8) + b[3];
      var c = String(n % 100000000);
      while (c.length < 8) c = '0' + c;
      if (codigos.indexOf(c) < 0) codigos.push(c);
    }
    return codigos.map(function (c) { return { codigo: c, usado: false }; });
  }
  function formatoRespaldo(c) { return c.slice(0, 4) + ' ' + c.slice(4); }

  function uriOtpauth(etiqueta, clave) {
    return 'otpauth://totp/' + encodeURIComponent(EMISOR) + ':' + encodeURIComponent(etiqueta) +
      '?secret=' + clave + '&issuer=' + encodeURIComponent(EMISOR) +
      '&algorithm=SHA1&digits=6&period=30';
  }

  function svgQr(texto) {
    var q = qrcode(0, 'M');
    q.addData(texto);
    q.make();
    return q.createSvgTag({ cellSize: 4, margin: 8, scalable: true, title: 'Código QR de configuración del Portal de Práctica 2FA' });
  }

  function hora(ms) {
    return new Date(ms).toLocaleTimeString('es-CO', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  function nuevoFactor() {
    var numero = estado.factores.length + 1;
    var f = {
      id: 'f' + numero,
      clave: claveNueva(),
      etiqueta: numero === 1 ? estado.nombre : estado.nombre + ' (' + numero + ')',
      creado: Date.now(),
      estado: 'PENDIENTE'
    };
    estado.factores.push(f);
    return f;
  }

  // Revisa un código contra los factores activos (o el pendiente) y explica el rechazo.
  function revisarCodigo(texto, candidatos) {
    var limpio = String(texto).replace(/\D/g, '');
    if (limpio.length !== 6) return { ok: false, motivo: 'largo' };
    var ahora = Date.now();
    for (var i = 0; i < candidatos.length; i++) {
      if (Totp.desfase(candidatos[i].clave, limpio, ahora, MARGEN_ACEPTADO) !== null) {
        return { ok: true, factor: candidatos[i] };
      }
    }
    // Código de otra entrada de la aplicación: una revocada, o la anterior mientras se registra
    // el factor nuevo.
    var otros = estado.factores.filter(function (f) {
      return candidatos.indexOf(f) < 0 && f.estado !== 'PENDIENTE';
    });
    for (i = 0; i < otros.length; i++) {
      if (Totp.desfase(otros[i].clave, limpio, ahora, MARGEN_ACEPTADO) !== null) {
        return { ok: false, motivo: otros[i].estado === 'REVOCADO' ? 'revocado' : 'anterior', esperada: candidatos[0] };
      }
    }
    for (i = 0; i < candidatos.length; i++) {
      var d = Totp.desfase(candidatos[i].clave, limpio, ahora, MARGEN_DIAGNOSTICO);
      if (d !== null) return { ok: false, motivo: 'hora', minutos: Math.round(d * Totp.PERIODO / 60) };
    }
    return { ok: false, motivo: 'incorrecto' };
  }

  function mensajeRechazo(r) {
    if (r.motivo === 'largo') return 'El código de verificación tiene 6 dígitos. Escribe solo los números que muestra tu aplicación.';
    if (r.motivo === 'anterior') return 'Ese código es de la <strong>entrada anterior</strong> de tu aplicación. Escanea el QR nuevo y escribe el código de la entrada <strong>' + esc(r.esperada.etiqueta) + '</strong>.';
    if (r.motivo === 'revocado') return 'Ese código sale de la <strong>entrada antigua</strong> de tu aplicación, la del factor que revocaste. Ya no sirve: usa la entrada nueva y borra la vieja de la aplicación (§6 de tu guía).';
    if (r.motivo === 'hora') {
      var cuando = r.minutos === 0 ? 'unos segundos de diferencia' :
        (Math.abs(r.minutos) + (Math.abs(r.minutos) === 1 ? ' minuto ' : ' minutos ') + (r.minutos > 0 ? 'en el futuro' : 'en el pasado'));
      return 'Ese código sería válido con la hora corrida (' + cuando + '). <strong>La hora de tu teléfono no coincide con la real.</strong> Activa la fecha y hora automáticas (Guía 00, §5) y escribe el código que aparezca después.';
    }
    return 'Código incorrecto. Revisa que estés mirando la entrada <strong>' + esc(EMISOR) + '</strong> de tu aplicación y escribe el código que se ve <em>ahora</em> (cambia cada 30 segundos).';
  }

  // ---------------------------------------------------------------- piezas de interfaz

  function cicloHtml() {
    var actual = CICLO.indexOf(estado.cuenta);
    var partes = CICLO.map(function (e, i) {
      var clase = i === actual ? 'actual' : (i < actual ? 'pasado' : '');
      return '<li class="' + clase + '"' + (i === actual ? ' aria-current="step"' : '') + '>' + e + '</li>';
    });
    return '<ol class="ciclo" aria-label="Estado de tu cuenta de práctica">' +
      partes.join('<li class="flecha" aria-hidden="true">→</li>') + '</ol>';
  }

  function relojHtml() {
    return '<p class="reloj" aria-live="off">Hora de este computador: <strong data-reloj="hora">' + hora(Date.now()) +
      '</strong> · el código de tu aplicación cambia en <strong data-reloj="restantes">' +
      Totp.segundosRestantes(Date.now()) + '</strong> s</p>';
  }

  function avisoHtml(tipo, html) {
    return '<div class="aviso aviso-' + tipo + '" role="' + (tipo === 'error' ? 'alert' : 'status') + '">' + html + '</div>';
  }

  function formularioCodigo(id, etiqueta, ayuda, textoBoton) {
    return '<form id="' + id + '" autocomplete="off" novalidate>' +
      '<label for="' + id + '-campo">' + etiqueta + '</label>' +
      '<input id="' + id + '-campo" class="codigo" type="text" inputmode="numeric" pattern="[0-9 ]*" maxlength="9" autocomplete="one-time-code" required>' +
      (ayuda ? '<p class="ayuda">' + ayuda + '</p>' : '') +
      '<div id="' + id + '-mensaje"></div>' +
      '<div class="acciones"><button class="boton" type="submit">' + textoBoton + '</button></div>' +
      '</form>';
  }

  function bloqueQr(factor, contexto) {
    return '<div class="qr-bloque">' +
      '<div class="qr">' + svgQr(uriOtpauth(factor.etiqueta, factor.clave)) + '</div>' +
      '<div style="flex:1;min-width:240px">' +
      '<ol class="pasos">' +
      '<li><strong>En el teléfono:</strong> abre tu aplicación Authenticator y toca la opción para <strong>agregar una cuenta</strong>.</li>' +
      '<li>Elige <strong>escanear un código QR</strong> y apunta la cámara a este código. (Los nombres exactos están en la §' + (contexto === 'nuevo' ? '7' : '2') + ' de tu guía.)</li>' +
      '<li>En la aplicación aparece <strong>' + esc(EMISOR) + '</strong> con un código de 6 dígitos que cambia cada 30 segundos.</li>' +
      '<li><strong>En el computador:</strong> escribe ese código abajo.</li>' +
      '</ol>' +
      '<p class="ayuda">¿Abriste este portal en el mismo teléfono donde está la aplicación? No puedes escanear tu propia pantalla: toca <a href="' + esc(uriOtpauth(factor.etiqueta, factor.clave)) + '">agregar en este teléfono</a> o usa la clave de configuración.</p>' +
      '<details><summary>¿No puedes escanear? Usa la clave de configuración</summary>' +
      '<p class="ayuda">En la aplicación elige la opción de <strong>introducir la clave manualmente</strong> y usa estos datos:</p>' +
      '<dl class="datos"><dt>Cuenta</dt><dd>' + esc(factor.etiqueta) + '</dd>' +
      '<dt>Emisor</dt><dd>' + esc(EMISOR) + '</dd>' +
      '<dt>Tipo</dt><dd>Basado en tiempo (TOTP), 6 dígitos, 30 s</dd></dl>' +
      '<div class="clave">' + agrupar(factor.clave) + '</div>' +
      '</details>' +
      '</div></div>' +
      avisoHtml('alerta', 'Aquí puedes ver el QR y la clave porque es un sitio de práctica. En tu cuenta real son <strong>secretos</strong>: no los fotografíes para enviarlos ni los compartas con nadie.');
  }

  function listaRespaldo(mostrarUsados) {
    return '<ul class="codigos-respaldo">' + estado.respaldo.map(function (c) {
      if (c.usado && !mostrarUsados) return '';
      return '<li class="' + (c.usado ? 'usado' : '') + '">' + formatoRespaldo(c.codigo) +
        (c.usado ? '<span class="visualmente-oculto"> (usado)</span>' : '') + '</li>';
    }).join('') + '</ul>';
  }

  // ---------------------------------------------------------------- vistas

  var vistas = {};

  vistas.inicio = function () {
    var hechos = competencias().filter(function (c) { return c.logrado; }).length;
    return '<h1>Practica tu segundo factor sin arriesgar tu cuenta</h1>' +
      '<p class="entradilla">Este portal imita el sitio de una organización ficticia. Aquí puedes registrar tu aplicación Authenticator, iniciar sesión, fingir que pierdes el teléfono y recuperar el acceso. Si te equivocas, no pasa nada: vuelves a empezar.</p>' +
      '<div class="rejilla">' +
      '<section class="tarjeta"><h2>Lo que este sitio promete</h2><ul>' +
      '<li>Nunca te pide una contraseña ni un correo.</li>' +
      '<li>No tiene servidor: lo que haces se guarda solo en este navegador.</li>' +
      '<li>Sus QR, claves y códigos son de práctica: puedes verlos sin riesgo.</li></ul></section>' +
      '<section class="tarjeta"><h2>Cómo usarlo con el taller</h2><ul>' +
      '<li><strong>Parte 1:</strong> <a href="#cuenta">Mi cuenta</a> → crear la cuenta de práctica.</li>' +
      '<li><strong>Parte 3:</strong> <a href="#cuenta">Mi cuenta</a> → cerrar sesión y volver a entrar.</li>' +
      '<li><strong>Parte 4:</strong> <a href="#cuenta">Mi cuenta</a> → «Perdí mi teléfono».</li>' +
      '<li><strong>Parte 5:</strong> <a href="#escenarios">Escenarios</a>.</li>' +
      '<li>Al final: <a href="#resumen">Resumen</a>.</li></ul></section>' +
      '</div>' +
      '<section class="tarjeta"><h2>Tu avance</h2>' + cicloHtml() +
      '<div class="barra-progreso" aria-hidden="true"><span style="width:' + Math.round(hechos / 6 * 100) + '%"></span></div>' +
      '<p class="suave">' + hechos + ' de 6 competencias del taller.</p>' +
      '<div class="acciones"><a class="boton" href="#cuenta">' + (estado.nombre ? 'Ir a mi cuenta de práctica' : 'Crear mi cuenta de práctica') + '</a>' +
      '<a class="boton boton-secundario" href="#escenarios">Ver los escenarios</a></div></section>' +
      (almacenOk ? '' : avisoHtml('alerta', 'Este navegador no deja guardar datos (¿ventana privada?). Puedes practicar, pero tu avance se perderá al cerrar la pestaña.'));
  };

  // "Mi cuenta" muestra siempre el siguiente paso del ciclo de vida.
  vistas.cuenta = function () {
    if (!estado.nombre) return pasoNombre();
    var pendiente = factorPendiente();
    if (pendiente && factoresEn('ACTIVO').length === 0 && !perdido()) return pasoVincular(pendiente, 'alta');
    if (!estado.sesion) return pasoIngreso();
    if (perdido()) return pasoVincular(pendiente || nuevoFactorGuardado(), 'nuevo');
    if (!estado.respaldoConfirmado) return pasoRespaldo();
    return panel();
  };

  function nuevoFactorGuardado() { var f = nuevoFactor(); guardar(); return f; }

  function pasoNombre() {
    var b = aleatorio(2);
    var sugerido = 'estudiante-' + (1000 + ((b[0] << 8) | b[1]) % 9000);
    return '<h1>Crea tu cuenta de práctica</h1>' +
      '<p class="entradilla">Parte 1 del taller. Solo necesitas un nombre inventado.</p>' +
      '<section class="tarjeta"><form id="form-nombre" novalidate>' +
      '<label for="campo-nombre">Nombre de usuario de práctica</label>' +
      '<input id="campo-nombre" type="text" maxlength="30" value="' + sugerido + '" autocomplete="off" spellcheck="false">' +
      '<p class="ayuda">Usa un apodo. No uses tu correo, tu nombre completo ni tu documento.</p>' +
      '<div id="form-nombre-mensaje"></div>' +
      avisoHtml('info', 'En un sitio real aquí también escribirías tu contraseña. Este portal no la pide para que nunca escribas una contraseña real en un sitio de práctica.') +
      '<div class="acciones"><button class="boton" type="submit">Continuar</button></div>' +
      '</form></section>';
  }

  function pasoVincular(factor, contexto) {
    var titulo = contexto === 'nuevo' ? 'Registra tu factor nuevo' : 'Vincula tu aplicación';
    var intro = contexto === 'nuevo'
      ? 'Entraste con un código de respaldo. Ahora registra la aplicación en tu teléfono «nuevo». En la aplicación aparecerá una entrada más, <strong>' + esc(factor.etiqueta) + '</strong>: es la que vale desde ahora.'
      : 'Escanea el QR con la aplicación que elegiste y confirma con el primer código. Sigue la §2 de tu guía.';
    return '<h1>' + titulo + '</h1>' + cicloHtml() +
      '<p class="entradilla">' + intro + '</p>' +
      '<section class="tarjeta">' + bloqueQr(factor, contexto) + '</section>' +
      '<section class="tarjeta">' +
      formularioCodigo('form-vincular', 'Código de verificación que muestra tu aplicación', null, 'Verificar') +
      relojHtml() + '</section>' +
      (contexto === 'alta' ? '<p><button class="boton-enlace" data-accion="otro-nombre">Usar otro nombre</button></p>' : '');
  }

  function pasoRespaldo() {
    return '<h1>Guarda tus códigos de respaldo</h1>' + cicloHtml() +
      avisoHtml('exito', '¡Listo! Tu aplicación quedó vinculada: estado <code>FACTOR_VERIFICADO</code>.') +
      '<p class="entradilla">Estos códigos te dejan entrar <strong>sin el teléfono</strong>. Cada uno sirve una sola vez. Los usarás en la Parte 4 del taller.</p>' +
      '<section class="tarjeta">' + listaRespaldo(true) +
      '<p class="suave">En tu cuenta institucional, Google los llama <em>«Códigos de verificación alternativos»</em> y son 10. Aquí son 8 y de práctica.</p>' +
      '<form id="form-respaldo" novalidate>' +
      '<label class="casilla"><input type="checkbox" id="campo-respaldo"> Los anoté fuera del teléfono (en papel o en un gestor de contraseñas).</label>' +
      '<div id="form-respaldo-mensaje"></div>' +
      '<div class="acciones"><button class="boton" type="submit">Confirmar</button></div>' +
      '</form></section>';
  }

  var modoIngreso = 'codigo';

  function pasoIngreso() {
    var html = '<h1>Iniciar sesión</h1>' + cicloHtml();
    html += '<section class="tarjeta"><dl class="datos"><dt>Usuario</dt><dd>' + esc(estado.nombre) + '</dd>' +
      '<dt>Contraseña</dt><dd class="suave">(se omite en la práctica)</dd></dl>';
    if (perdido()) {
      html += avisoHtml('alerta', '<strong>Finges que perdiste el teléfono.</strong> La opción del código de la aplicación no está disponible. Entra con uno de tus códigos de respaldo.');
      modoIngreso = 'respaldo';
    }
    if (modoIngreso === 'codigo') {
      html += '<h2>Segundo paso</h2>' +
        formularioCodigo('form-ingreso', 'Código de verificación de tu aplicación', 'Abre la entrada <strong>' + esc(EMISOR) + '</strong> y escribe el código que se ve ahora.', 'Entrar') +
        relojHtml() +
        '<p><button class="boton-enlace" data-accion="modo-respaldo">Probar otra manera: usar un código de respaldo</button></p>';
    } else {
      html += '<h2>Segundo paso: código de respaldo</h2>' +
        formularioCodigo('form-ingreso-respaldo', 'Código de respaldo (8 dígitos)', 'Cada código de respaldo sirve una sola vez. Te quedan ' + respaldoDisponible().length + '.', 'Entrar') +
        (perdido() ? '' : '<p><button class="boton-enlace" data-accion="modo-codigo">Volver a usar el código de la aplicación</button></p>');
    }
    html += '</section>';
    if (perdido() && respaldoDisponible().length === 0) {
      html += avisoHtml('error', 'No te quedan códigos de respaldo. En una cuenta real este sería el estado <code>BLOQUEADA</code>: solo quedaría el proceso de recuperación del servicio o la mesa de ayuda. En la práctica, puedes <button class="boton-enlace" data-accion="reiniciar">reiniciar la práctica</button>.');
    }
    return html;
  }

  function panel() {
    var activos = factoresEn('ACTIVO');
    var html = '<h1>Mi cuenta de práctica</h1>' + cicloHtml();
    if (estado.cuenta === 'RECUPERADA') {
      html += avisoHtml('exito', '<strong>Recuperaste el acceso sin el teléfono</strong>: estado <code>RECUPERADA</code>. El factor anterior quedó <code>REVOCADO</code>. Borra su entrada antigua de la aplicación y comprueba que su código ya no te deja entrar (cierra sesión e inténtalo).');
    }
    html += '<div class="rejilla">' +
      '<section class="tarjeta"><h2>Segundo factor</h2><ul class="factores">' +
      estado.factores.filter(function (f) { return f.estado !== 'PENDIENTE'; }).map(function (f) {
        return '<li><span>Aplicación Authenticator · <strong>' + esc(f.etiqueta) + '</strong></span>' +
          '<span class="etiqueta etiqueta-' + f.estado.toLowerCase() + '">' + f.estado + '</span></li>';
      }).join('') + '</ul>' +
      '<p class="suave">Factores activos: ' + activos.length + '.</p></section>' +
      '<section class="tarjeta"><h2>Códigos de respaldo</h2>' +
      '<p>Te quedan <strong>' + respaldoDisponible().length + '</strong> de ' + estado.respaldo.length + '.</p>' +
      '<details><summary>Ver los códigos</summary>' + listaRespaldo(true) + '</details>' +
      '<div class="acciones"><button class="boton boton-secundario" data-accion="regenerar">Generar códigos nuevos</button></div>' +
      '<p class="ayuda">Generar códigos nuevos anula todos los anteriores.</p></section>' +
      '</div>';
    html += '<section class="tarjeta"><h2>¿Qué sigue?</h2>' +
      '<div class="acciones">' +
      '<button class="boton" data-accion="cerrar-sesion">Cerrar sesión y volver a entrar</button>' +
      '<button class="boton boton-peligro" data-accion="perdi">Perdí mi teléfono</button>' +
      '</div>' +
      '<p class="ayuda">«Perdí mi teléfono» es la Parte 4 del taller: el portal fingirá que no tienes la aplicación.</p>' +
      '</section>';
    html += '<section class="tarjeta"><h2>Actividad reciente</h2><ul class="suave">' +
      estado.historial.slice(0, 8).map(function (h) { return '<li>' + hora(h.t) + ' · ' + esc(h.texto) + '</li>'; }).join('') +
      '</ul><div class="acciones"><button class="boton boton-secundario" data-accion="reiniciar">Reiniciar la práctica</button></div></section>';
    return html;
  }

  // ---------------------------------------------------------------- escenarios

  // Orden aleatorio de las opciones, pero con la respuesta correcta rotando de posición entre
  // escenarios: así su lugar no delata la respuesta.
  function ordenDe(esc_, n) {
    var orden = estado.ordenEscenarios[esc_.id];
    if (!orden || orden.length !== esc_.opciones.length) {
      orden = esc_.opciones.map(function (_, i) { return i; });
      for (var i = orden.length - 1; i > 0; i--) {
        var j = aleatorio(1)[0] % (i + 1);
        var t = orden[i]; orden[i] = orden[j]; orden[j] = t;
      }
      if (estado.desplazamiento === undefined) estado.desplazamiento = aleatorio(1)[0] % orden.length;
      var destino = (n + estado.desplazamiento) % orden.length;
      var actual = orden.indexOf(esc_.correcta);
      orden[actual] = orden[destino];
      orden[destino] = esc_.correcta;
      estado.ordenEscenarios[esc_.id] = orden;
      guardar();
    }
    return orden;
  }

  function maquetaHtml(m) {
    if (m.tipo === 'navegador') {
      return '<div class="maqueta" aria-label="Pantalla simulada de un navegador"><div class="maqueta-barra"><span aria-hidden="true">🔒</span><span class="maqueta-url">' + esc(m.url) + '</span></div>' +
        '<div class="maqueta-cuerpo"><strong>' + esc(m.titulo) + '</strong><p class="suave" style="margin:6px 0 0">⚠ ' + esc(m.aviso) + '</p></div></div>';
    }
    if (m.tipo === 'notificaciones') {
      return '<div class="maqueta-telefono" aria-label="Pantalla simulada de un teléfono">' + m.textos.map(function (t) {
        return '<div class="notificacion"><small>Cuenta de Google · ' + esc(m.hora) + '</small>' + esc(t) + '<small>Sí / No, no soy yo</small></div>';
      }).join('') + '</div>';
    }
    if (m.tipo === 'llamada') {
      return '<div class="maqueta-telefono" style="text-align:center" aria-label="Llamada simulada"><p class="suave" style="margin:0">Llamada entrante</p><h3 style="margin:6px 0">' + esc(m.quien) + '</h3><p class="suave">' + esc(m.numero) + '</p></div>';
    }
    if (m.tipo === 'chat') {
      return '<div class="maqueta-telefono" aria-label="Chat simulado"><small class="suave">' + esc(m.quien) + '</small><div class="burbuja">' + esc(m.texto) + '<div class="qr-falso" role="img" aria-label="Imagen de un código QR"></div></div></div>';
    }
    if (m.tipo === 'ajuste') {
      return '<div class="maqueta-telefono" aria-label="Ajustes simulados del teléfono"><div class="interruptor"><span>' + esc(m.ajuste) + '</span><span aria-label="desactivado"></span></div>' +
        '<div class="notificacion" style="margin-top:12px">' + esc(m.error) + '</div></div>';
    }
    return '';
  }

  vistas.escenarios = function () {
    var lista = window.ESCENARIOS || [];
    var respondidos = lista.filter(function (e) { return e.id in estado.escenarios; });
    var aciertos = respondidos.filter(function (e) { return estado.escenarios[e.id] === e.correcta; }).length;
    var html = '<h1>¿Aprobarías esto?</h1>' +
      '<p class="entradilla">Parte 5 del taller. Seis situaciones reales. Decide qué harías; después verás la señal que había que notar y por qué.</p>' +
      '<p class="suave">Respondidos: ' + respondidos.length + ' de ' + lista.length + ' · acertados: ' + aciertos + '.</p>';
    lista.forEach(function (e, n) {
      var elegido = estado.escenarios[e.id];
      var respondido = elegido !== undefined;
      html += '<section class="tarjeta" id="escenario-' + e.id + '"><div class="escenario-cabeza"><h2>' + (n + 1) + '. ' + esc(e.titulo) + '</h2>' +
        (respondido ? '<span class="etiqueta ' + (elegido === e.correcta ? 'etiqueta-activo' : '') + '">' + (elegido === e.correcta ? 'Acertado' : 'Revisar') + '</span>' : '') + '</div>' +
        '<p>' + esc(e.situacion) + '</p>' + maquetaHtml(e.maqueta) +
        '<div class="opciones" role="group" aria-label="Opciones">';
      ordenDe(e, n).forEach(function (i) {
        var clase = !respondido ? '' : (i === e.correcta ? 'correcta' : (i === elegido ? 'incorrecta' : ''));
        html += '<button class="opcion ' + clase + '" data-escenario="' + e.id + '" data-opcion="' + i + '"' + (respondido ? ' disabled' : '') + '>' +
          (respondido && i === e.correcta ? '✓ ' : (respondido && i === elegido ? '✗ ' : '')) + esc(e.opciones[i]) + '</button>';
      });
      html += '</div>';
      if (respondido) {
        html += '<div class="retro">' + avisoHtml(elegido === e.correcta ? 'exito' : 'alerta',
          (elegido === e.correcta ? '<strong>Bien.</strong> ' : '<strong>No es la mejor opción.</strong> ') +
          '<strong>La señal:</strong> ' + esc(e.senal) + '<br><strong>Por qué:</strong> ' + esc(e.porque)) +
          '<button class="boton-enlace" data-reintentar="' + e.id + '">Volver a intentar</button></div>';
      }
      html += '</section>';
    });
    if (respondidos.length === lista.length && lista.length) {
      html += '<div class="acciones"><a class="boton" href="#resumen">Ver mi resumen</a></div>';
    }
    return html;
  };

  // ---------------------------------------------------------------- resumen

  function competencias() {
    var lista = window.ESCENARIOS || [];
    var resueltos = lista.filter(function (e) { return e.id in estado.escenarios; }).length;
    var a = estado.autodeclaradas;
    var huboFactor = estado.factores.some(function (f) { return f.estado !== 'PENDIENTE'; });
    return [
      { n: 1, titulo: 'Registro un segundo factor con una aplicación', portal: huboFactor, textoPortal: 'Portal: aplicación vinculada (`FACTOR_VERIFICADO`).', clave: 'uq1', textoPropio: 'Mi cuenta UQ muestra «Autenticador» en la verificación en dos pasos.' },
      { n: 2, titulo: 'Tengo un plan B', portal: estado.respaldoConfirmado, textoPortal: 'Portal: códigos de respaldo confirmados (`CON_RESPALDO`).', clave: 'uq2', textoPropio: 'Generé los códigos de verificación alternativos de mi cuenta UQ y están guardados fuera del teléfono.' },
      { n: 3, titulo: 'Inicio sesión con el factor', portal: estado.ingresoConCodigo, textoPortal: 'Portal: entré con el código de la aplicación.', clave: 'uq3', textoPropio: 'Entré a mi cuenta UQ (en ventana privada) con el código de la aplicación.' },
      { n: 4, titulo: 'Recupero el acceso sin el teléfono', portal: estado.recuperada, textoPortal: 'Portal: `RECUPERADA`, con un factor nuevo y el anterior `REVOCADO`.' },
      { n: 5, titulo: 'Reconozco un intento de engaño', portal: resueltos === lista.length && lista.length > 0, textoPortal: 'Escenarios resueltos: ' + resueltos + ' de ' + lista.length + '.' },
      { n: 6, titulo: 'Protejo los secretos', portal: null, clave: 'c6', textoPropio: 'Ningún QR, clave ni código de mi cuenta real salió de mi pantalla.' }
    ].map(function (c) {
      var propio = c.clave ? !!a[c.clave] : null;
      var partes = [c.portal, propio].filter(function (v) { return v !== null; });
      c.logrado = partes.length > 0 && partes.every(Boolean);
      c.parcial = !c.logrado && partes.some(Boolean);
      return c;
    });
  }

  function codigoTexto(t) { return esc(t).replace(/`([^`]+)`/g, '<code>$1</code>'); }

  vistas.resumen = function () {
    var cs = competencias();
    var hechos = cs.filter(function (c) { return c.logrado; }).length;
    var html = '<h1>Resumen de competencias</h1>' +
      '<p class="entradilla">Lo que el portal pudo comprobar se marca solo. Lo que pasó en tu cuenta real lo marcas tú: el portal no puede verla, y está bien que así sea.</p>' +
      '<div class="barra-progreso" aria-hidden="true"><span style="width:' + Math.round(hechos / 6 * 100) + '%"></span></div>' +
      '<p class="suave">' + hechos + ' de 6 competencias logradas.</p>' +
      '<section class="tarjeta"><ol class="competencias">';
    cs.forEach(function (c) {
      html += '<li><span class="marca-estado ' + (c.logrado ? 'logrado' : (c.parcial ? 'parcial' : '')) + '" aria-label="' + (c.logrado ? 'logrado' : (c.parcial ? 'en progreso' : 'pendiente')) + '">' + (c.logrado ? '✓' : c.n) + '</span>' +
        '<div><strong>' + esc(c.titulo) + '</strong>';
      if (c.portal !== null) html += '<p class="sub">' + (c.portal ? '✓ ' : '○ ') + codigoTexto(c.textoPortal) + '</p>';
      if (c.clave) {
        html += '<div class="sub"><label class="casilla"><input type="checkbox" data-autodeclarada="' + c.clave + '"' + (estado.autodeclaradas[c.clave] ? ' checked' : '') + '> ' + esc(c.textoPropio) + '</label></div>';
      }
      html += '</div></li>';
    });
    html += '</ol></section>' +
      avisoHtml('info', '<strong>La competencia 4 es la que más importa.</strong> Una cuenta con segundo factor y sin plan de recuperación cambia el riesgo de «me roban la cuenta» por «pierdo la cuenta».') +
      '<div class="acciones"><button class="boton boton-secundario" onclick="window.print()">Imprimir resumen</button></div>';
    return html;
  };

  // ---------------------------------------------------------------- acciones

  function mostrar(idForm, tipo, html) {
    var caja = document.getElementById(idForm + '-mensaje');
    if (caja) caja.innerHTML = avisoHtml(tipo, html);
  }

  function alEnviar(e) {
    var form = e.target;
    if (!form.id) return;
    e.preventDefault();
    var campo = form.querySelector('input[type="text"]');
    var valor = campo ? campo.value.trim() : '';

    if (form.id === 'form-nombre') {
      if (valor.length < 2) return mostrar(form.id, 'error', 'Escribe un nombre de al menos 2 caracteres.');
      if (/@/.test(valor)) return mostrar(form.id, 'error', 'Eso parece un correo. Usa un nombre inventado: este sitio nunca debe recibir datos reales.');
      estado.nombre = valor;
      nuevoFactor();
      registrar('Cuenta de práctica creada');
      guardar();
      return pintar();
    }

    if (form.id === 'form-vincular') {
      var pendiente = factorPendiente();
      var r = revisarCodigo(valor, pendiente ? [pendiente] : []);
      if (!r.ok) return mostrar(form.id, 'error', mensajeRechazo(r));
      var eraPerdida = perdido();
      pendiente.estado = 'ACTIVO';
      if (eraPerdida) {
        estado.factores.forEach(function (f) { if (f !== pendiente && f.estado === 'ACTIVO') f.estado = 'REVOCADO'; });
        estado.cuenta = 'RECUPERADA';
        estado.recuperada = true;
        registrar('Factor nuevo registrado; el anterior quedó revocado');
      } else {
        estado.cuenta = 'FACTOR_VERIFICADO';
        estado.respaldo = codigosRespaldoNuevos();
        estado.sesion = true;
        registrar('Aplicación vinculada');
      }
      guardar();
      return pintar();
    }

    if (form.id === 'form-respaldo') {
      if (!document.getElementById('campo-respaldo').checked) {
        return mostrar(form.id, 'error', 'Marca la casilla cuando hayas anotado los códigos. Sin ellos, perder el teléfono es perder la cuenta.');
      }
      estado.respaldoConfirmado = true;
      estado.cuenta = 'CON_RESPALDO';
      registrar('Códigos de respaldo guardados');
      guardar();
      return pintar();
    }

    if (form.id === 'form-ingreso') {
      var r2 = revisarCodigo(valor, factoresEn('ACTIVO'));
      if (!r2.ok) return mostrar(form.id, 'error', mensajeRechazo(r2));
      estado.sesion = true;
      estado.ingresoConCodigo = true;
      registrar('Inicio de sesión con el código de la aplicación');
      guardar();
      return pintar();
    }

    if (form.id === 'form-ingreso-respaldo') {
      var limpio = valor.replace(/\D/g, '');
      var c = estado.respaldo.filter(function (x) { return x.codigo === limpio; })[0];
      if (!c) return mostrar(form.id, 'error', 'Ese no es uno de tus códigos de respaldo. Son de 8 dígitos y los anotaste en la Parte 1.');
      if (c.usado) return mostrar(form.id, 'error', 'Ese código de respaldo ya se usó. Cada uno sirve una sola vez: prueba con otro.');
      c.usado = true;
      estado.sesion = true;
      modoIngreso = 'codigo';
      registrar('Inicio de sesión con un código de respaldo (quedan ' + respaldoDisponible().length + ')');
      if (perdido() && !factorPendiente()) nuevoFactor();
      guardar();
      return pintar();
    }
  }

  function alHacerClic(e) {
    var b = e.target.closest('[data-accion],[data-escenario],[data-reintentar]');
    if (!b) return;

    if (b.dataset.escenario) {
      estado.escenarios[b.dataset.escenario] = Number(b.dataset.opcion);
      guardar();
      pintar('escenario-' + b.dataset.escenario);
      return;
    }
    if (b.dataset.reintentar) {
      delete estado.escenarios[b.dataset.reintentar];
      delete estado.ordenEscenarios[b.dataset.reintentar];
      guardar();
      pintar('escenario-' + b.dataset.reintentar);
      return;
    }

    switch (b.dataset.accion) {
      case 'otro-nombre':
        estado = estadoInicial(); guardar(); break;
      case 'modo-respaldo': modoIngreso = 'respaldo'; break;
      case 'modo-codigo': modoIngreso = 'codigo'; break;
      case 'cerrar-sesion':
        estado.sesion = false; modoIngreso = 'codigo';
        registrar('Sesión cerrada'); guardar(); break;
      case 'perdi':
        if (respaldoDisponible().length === 0) {
          window.alert('No te quedan códigos de respaldo. Genera códigos nuevos antes de practicar la pérdida del teléfono.');
          return;
        }
        if (!window.confirm('El portal fingirá que perdiste el teléfono: cerrará tu sesión y no aceptará el código de la aplicación. Para volver a entrar necesitarás uno de tus códigos de respaldo. ¿Continuar?')) return;
        estado.cuenta = 'DISPOSITIVO_PERDIDO';
        estado.sesion = false;
        registrar('Teléfono marcado como perdido');
        guardar(); break;
      case 'regenerar':
        if (!window.confirm('Se generarán 8 códigos nuevos y los anteriores dejarán de servir. ¿Continuar?')) return;
        estado.respaldo = codigosRespaldoNuevos();
        registrar('Códigos de respaldo regenerados');
        guardar(); break;
      case 'reiniciar':
        if (!window.confirm('Se borrará toda tu práctica en este navegador (cuenta, códigos, escenarios y resumen). Recuerda borrar también la entrada del portal en tu aplicación. ¿Continuar?')) return;
        estado = estadoInicial(); modoIngreso = 'codigo'; guardar();
        location.hash = '#cuenta'; break;
      default: return;
    }
    pintar();
  }

  function alCambiar(e) {
    var clave = e.target.dataset && e.target.dataset.autodeclarada;
    if (!clave) return;
    estado.autodeclaradas[clave] = e.target.checked;
    guardar();
    pintar();
  }

  // ---------------------------------------------------------------- render

  function rutaActual() {
    var r = (location.hash || '#inicio').slice(1);
    return vistas[r] ? r : 'inicio';
  }

  function pintar(anclaFoco) {
    var ruta = rutaActual();
    var vista = document.getElementById('vista');
    vista.innerHTML = vistas[ruta]();
    document.querySelectorAll('.navegacion a').forEach(function (a) {
      if (a.dataset.ruta === ruta) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
    });
    var destino = anclaFoco && document.getElementById(anclaFoco);
    if (destino) { destino.scrollIntoView({ block: 'start' }); return; }
    var campo = vista.querySelector('input.codigo, #campo-nombre');
    if (campo) campo.focus({ preventScroll: true });
  }

  function tic() {
    var ahora = Date.now();
    document.querySelectorAll('[data-reloj="hora"]').forEach(function (n) { n.textContent = hora(ahora); });
    document.querySelectorAll('[data-reloj="restantes"]').forEach(function (n) { n.textContent = Totp.segundosRestantes(ahora); });
  }

  document.addEventListener('submit', alEnviar);
  document.addEventListener('click', alHacerClic);
  document.addEventListener('change', alCambiar);
  window.addEventListener('hashchange', function () { pintar(); window.scrollTo(0, 0); document.getElementById('vista').focus({ preventScroll: true }); });
  window.addEventListener('storage', function (e) { if (e.key === CLAVE_ALMACEN) { estado = cargar(); pintar(); } });
  setInterval(tic, 1000);
  pintar();
})();
