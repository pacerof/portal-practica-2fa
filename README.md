# Portal de Práctica 2FA

Sitio estático del material de *Autenticación de doble factor con aplicaciones Authenticator*.
Especificación: `../referencia-2fa.md` §8. Escenarios: `../taller/escenarios.md`.

## Qué hace

- Alta con un nombre inventado → QR y clave de configuración → primer código → `FACTOR_VERIFICADO`.
- 8 códigos de respaldo de práctica → `CON_RESPALDO`.
- Inicio de sesión con el código (acepta ±30 s). Si el código corresponde a otra hora (hasta
  ±10 min), explica que la hora del teléfono está mal; si viene de una entrada revocada o de la
  anterior, lo dice.
- **Perdí mi teléfono** → `DISPOSITIVO_PERDIDO` → entrar con un código de respaldo → registrar un
  factor nuevo → el anterior queda `REVOCADO` → `RECUPERADA`.
- Seis escenarios con retroalimentación. Las opciones se mezclan y la respuesta correcta rota de
  posición entre escenarios.
- Resumen de las 6 competencias del taller: lo que el portal comprueba se marca solo; lo de la
  cuenta real lo marca el estudiante.

No hay servidor ni analítica. El estado vive en `localStorage` (clave `portal2fa.v1`) del navegador
del estudiante. El sitio nunca pide contraseña ni correo, y rechaza un nombre que parezca un correo.

## Archivos

| Archivo | Contenido |
|---|---|
| `index.html` | Estructura y banda de "sitio de práctica" |
| `estilos.css` | Estilos (modo claro y oscuro, móvil) |
| `app.js` | Vistas, ciclo de vida de la cuenta, escenarios y resumen |
| `totp.js` | TOTP RFC 6238 (SHA-1, 6 dígitos, 30 s) en JavaScript puro |
| `escenarios.js` | Datos de los escenarios (copia de `taller/escenarios.md`) |
| `vendor/qrcode.js` | [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) 1.4.4, licencia MIT, sin cambios |
| `pruebas-totp.js` | Pruebas con los vectores de RFC 2202, 4226 y 6238 |

## Probar

```bash
node practica/pruebas-totp.js
```

```bash
python3 -m http.server 8765 --bind 127.0.0.1 --directory practica
```

Luego abrir `http://localhost:8765`. También funciona abriendo `index.html` directamente.

Verificado el 2026-11-03 en el navegador: alta, código incorrecto, hora corrida, respaldo,
cierre de sesión, ingreso con código, pérdida, código de respaldo inválido y reutilizado, factor
nuevo, código de la entrada anterior y de la revocada, escenarios, resumen, vista móvil y modo
claro/oscuro. El QR generado se decodificó con OpenCV y coincide con el URI `otpauth://`.
**Falta:** escanearlo con las seis aplicaciones en teléfonos reales (Android e iOS).

## Publicar en GitHub Pages

```bash
./publicar-portal.sh pacerof/portal-practica-2fa
```

El script (en la raíz del material) corre las pruebas, crea el repositorio público si no existe,
sube **solo** el contenido de esta carpeta a `main`, activa GitHub Pages y muestra la URL. Debe
ejecutarse con `gh` iniciado en la cuenta **pacerof** (o en una cuenta colaboradora del repositorio).

URL: https://pacerof.github.io/portal-practica-2fa/ (ya anotada en `referencia-2fa.md` §8, el taller,
las guías y los decks).

## Mantenimiento

- Si cambia un escenario, se cambia primero en `taller/escenarios.md` y luego en `escenarios.js`.
- Si se cambia la estructura del estado, subir `version` en `app.js` y la clave de
  `localStorage`: los datos viejos se ignoran en lugar de romper el portal.
