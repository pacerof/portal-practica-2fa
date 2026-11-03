// Escenarios de la Parte 5 del taller. Fuente única: taller/escenarios.md — si cambia un
// escenario, se cambia allí primero y luego aquí, con el mismo texto.
// `maqueta` describe la pantalla simulada que acompaña la situación (ver dibujarMaqueta en app.js).
window.ESCENARIOS = [
  {
    id: 'E1',
    titulo: 'El dominio parecido',
    situacion: 'Te llega un correo: «Tu cuenta institucional será suspendida hoy si no confirmas tu verificación en dos pasos». El botón lleva a una página idéntica a la de inicio de sesión de Google. Pide tu contraseña y luego el código de tu aplicación.',
    maqueta: { tipo: 'navegador', url: 'https://accounts.google.com.verificacion-uq.co/signin', titulo: 'Iniciar sesión – Cuentas de Google', aviso: 'Tu cuenta será suspendida hoy' },
    opciones: [
      'Escribo la contraseña y el código: el código cambia en 30 s, no les sirve.',
      'Cierro la página, no escribo nada y entro a mi cuenta escribiendo yo la dirección.',
      'Escribo solo la contraseña, no el código.'
    ],
    correcta: 1,
    senal: 'El dominio real es lo que va justo antes de la primera «/»: aquí es verificacion-uq.co, no google.com. Además: urgencia y amenaza de suspensión.',
    porque: 'Un sitio falso puede reenviar tu contraseña y tu código al sitio real en el mismo instante: 30 segundos sobran. El código temporal no protege contra una página falsa; lo que protege es mirar el dominio antes de escribir. (Guía 00, §2.)'
  },
  {
    id: 'E2',
    titulo: 'La notificación que no pediste',
    situacion: 'Estás viendo una serie a las 11 p. m. Tu teléfono muestra una solicitud de inicio de sesión. No estás iniciando sesión en ningún lado. Un minuto después llega otra, y otra.',
    maqueta: { tipo: 'notificaciones', hora: '23:04', textos: ['¿Estás intentando iniciar sesión?', '¿Estás intentando iniciar sesión?', '¿Estás intentando iniciar sesión?'] },
    opciones: [
      'Apruebo una para que dejen de llegar.',
      'Rechazo, y cambio mi contraseña desde el sitio oficial.',
      'Las ignoro.'
    ],
    correcta: 1,
    senal: 'Tú no iniciaste ningún acceso. La insistencia es la técnica: se llama fatiga de MFA.',
    porque: 'Si llega una solicitud que no pediste, alguien ya tiene tu contraseña. Aprobar le da la entrada; ignorar deja la contraseña comprometida. Rechazar y cambiar la contraseña cierra las dos puertas. Por eso Microsoft Authenticator pide escribir un número que solo aparece en la pantalla de quien inicia sesión. (Guía 00; Guía 02 §5.2.)'
  },
  {
    id: 'E3',
    titulo: 'La llamada de «soporte»',
    situacion: 'Te llaman: «Hola, le hablamos de la mesa de ayuda de la Universidad. Detectamos actividad extraña en su cuenta. Para verificar que es usted, le va a llegar un código a su aplicación; léamelo, por favor». Saben tu nombre y tu programa.',
    maqueta: { tipo: 'llamada', quien: 'Mesa de ayuda UQ', numero: '+57 300 000 0000' },
    opciones: [
      'Leo el código: me llamaron ellos y saben mis datos.',
      'Cuelgo y, si me preocupa, llamo yo a la mesa de ayuda al número publicado en el sitio oficial.',
      'Les doy el código de respaldo en lugar del de la aplicación.'
    ],
    correcta: 1,
    senal: 'Te piden un código. Nadie legítimo lo necesita: ni la mesa de ayuda, ni un docente, ni Google.',
    porque: 'Quien te pide el código es quien está intentando entrar con tu contraseña en ese momento. Conocer tu nombre y tu programa no prueba nada: esos datos son públicos o fáciles de obtener.'
  },
  {
    id: 'E4',
    titulo: 'El QR por chat',
    situacion: 'Un compañero te escribe por chat: «Configuré el Authenticator de la cuenta del grupo de investigación, te mando la captura del QR para que también lo tengas».',
    maqueta: { tipo: 'chat', quien: 'Compañero', texto: 'Te mando la captura del QR para que también lo tengas 👇' },
    opciones: [
      'Lo escaneo: así ambos tenemos acceso.',
      'Le pido que no lo comparta, que borre la captura y que, si ya la envió, vuelva a configurar el factor para generar un QR nuevo.',
      'Lo escaneo y después borro la imagen.'
    ],
    correcta: 1,
    senal: 'Un código QR de configuración viajando por chat.',
    porque: 'El QR contiene la clave que genera todos los códigos, para siempre. Quien tenga la imagen —el chat, una copia de seguridad del chat, quien vea el teléfono— puede generar los mismos códigos. Una vez compartido, la única corrección es configurar de nuevo para que la clave cambie.'
  },
  {
    id: 'E5',
    titulo: 'El código que no funciona',
    situacion: 'Viajaste y desactivaste la hora automática del teléfono para poner la hora a mano. Ahora intentas entrar a tu cuenta institucional y Google dice que el código es incorrecto, aunque lo escribiste bien y antes de que cambiara.',
    maqueta: { tipo: 'ajuste', ajuste: 'Fecha y hora automáticas', valor: false, error: 'Código incorrecto. Vuelve a intentarlo.' },
    opciones: [
      'Borro la entrada de la aplicación y la vuelvo a agregar.',
      'Activo de nuevo la fecha y hora automáticas del teléfono y pruebo con el siguiente código.',
      'Desactivo la verificación en dos pasos.'
    ],
    correcta: 1,
    senal: 'El cambio en la hora del teléfono.',
    porque: 'El código se calcula con la clave y la hora. Si la hora del teléfono está corrida, el código es «correcto» para otra hora. Borrar la entrada es peligroso: si no puedes volver a escanear, pierdes ese factor. (Guía 00, §5; sección «Si algo sale mal» de cada guía.)'
  },
  {
    id: 'E6',
    titulo: 'La solicitud legítima',
    situacion: 'Estás en la sala de cómputo, abres el correo institucional en el computador, escribes tu contraseña y, segundos después, tu teléfono muestra una solicitud de inicio de sesión con el mismo navegador y la ciudad donde estás.',
    maqueta: { tipo: 'notificaciones', hora: '10:15', textos: ['¿Estás intentando iniciar sesión? · Chrome en Windows · Armenia, Quindío'] },
    opciones: [
      'La rechazo: nunca hay que aprobar notificaciones.',
      'La apruebo: la inicié yo, ahora mismo, y los datos coinciden.',
      'La ignoro y espero que expire.'
    ],
    correcta: 1,
    senal: 'Tú acabas de iniciar ese acceso, y lo que muestra el teléfono coincide con lo que estás haciendo (y, si aplica, el número coincide con el de la pantalla).',
    porque: 'El segundo factor no es desconfiar de todo: es comprobar que lo que apruebas corresponde a lo que tú hiciste. Si coincide, aprobar es lo correcto.'
  }
];
