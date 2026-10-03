# Seguridad del panel

El panel permite administrar escaneos e inventarios autenticados. Arráncalo con
una cuenta de mínimos privilegios y mantén separados los permisos de ejecución
y los permisos del operador cuando despliegues un worker privilegiado.

## Acceso local

`scopescan serve` solo permite escuchar en direcciones IP loopback, incluso con
Basic Auth configurada. Un despliegue remoto requiere un comando ASGI propio y
los controles de autenticación, proxy y TLS descritos aquí.

Por defecto acepta conexiones loopback y estos nombres Host: `localhost`,
`127.0.0.1` y `::1`. Un hostname controlado por el cliente no concede confianza:
Host se contrasta con una lista independiente antes de autenticar o servir datos.
No se aceptan comodines. Los puertos inválidos, incluido 0, se rechazan.

`SCOPESCAN_PANEL_HOSTS` añade nombres exactos separados por comas, por ejemplo
`panel.lab`. Esto no habilita acceso remoto sin autenticación ni añade orígenes.
`SCOPESCAN_PANEL_ORIGINS` define la lista completa de orígenes admitidos para
escrituras de navegador, por ejemplo `https://panel.lab,http://localhost:8000`.
La comparación normaliza mayúsculas y puerto predeterminado y rechaza URLs con
credenciales, fragmentos y puertos inválidos. Los defaults son HTTP loopback en
80/8000 y HTTPS loopback en 443. Si cambias el puerto local, configura el origen.

## Autenticación, TLS y proxy

Configurar `SCOPESCAN_PANEL_USER` y `SCOPESCAN_PANEL_PASSWORD` exige Basic Auth a
**todos** los clientes, incluido loopback. Usa una contraseña aleatoria larga,
injectada por un gestor de secretos o el entorno del servicio; no la guardes en
el repositorio, en parámetros de comandos ni en informes.

Basic Auth transmite credenciales reutilizables: usa HTTPS para todo acceso remoto.
El panel debe quedar detrás de un proxy TLS controlado, con puerto upstream solo
en loopback o red privada cerrada y reglas de firewall que impidan acceso directo.
Configura autenticación antes de exponer el proxy: una conexión upstream loopback
no prueba que el usuario del navegador sea local.

El middleware no usa `X-Forwarded-For`, `Forwarded` ni `X-Forwarded-Host` para conceder
confianza. El launcher desactiva el procesamiento de cabeceras proxy en Uvicorn.
Si usas tu propio comando ASGI, desactívalo también (`--no-proxy-headers`) o define
expresamente los proxies confiables y mantén autenticación obligatoria. Conserva
el Host público admitido al reenviar. No uses `forwarded-allow-ips=*`.

Los defaults HTTP locales usan cookies sin Secure. En un despliegue TLS con un
upstream HTTP configura `SCOPESCAN_PANEL_COOKIE_SECURE=1`, mantén SameSite=Strict y
protege el tránsito completo; sirve el dominio exclusivamente por HTTPS/HSTS.
La cookie también usa Secure automáticamente cuando ASGI termina TLS. No concedas confianza basándote
en una cabecera de esquema suministrada por el cliente.

## CSRF y clientes API

Las páginas HTML emiten una cookie HTTP-only SameSite=Strict con token firmado y
campos ocultos en cada formulario. JavaScript envía el token en `X-CSRF-Token`.
Toda escritura con cookie de sesión o señales de navegador requiere un token
válido que coincida con la cookie, además de un origen admitido si Origin/Referer
está presente. `Sec-Fetch-Site: cross-site` se rechaza también sin Origin.

Los scripts y curl sin cookies y sin cabeceras de navegador pueden llamar a las
rutas existentes. Deben usar Basic Auth cuando esté configurada. Si un script
reutiliza cookies de una página, debe copiar su token y enviarlo en X-CSRF-Token.
Basic Auth por sí sola no permite omitir CSRF en un navegador.

El token es propio de cada proceso del panel; reiniciar invalida sesiones. La
configuración actual contempla un único proceso ASGI; una instalación multiproceso
necesitaría almacenamiento/clave CSRF compartida y coordinación de jobs.

## Verificación local

`tests/test_panel_security.py` cubre Host malicioso, DNS rebinding simulado,
orígenes y puertos malformados, autenticación de loopback/proxy, formularios reales,
fetch con CSRF, clientes sin estado y claims atómicos. No realiza escaneos de red.
