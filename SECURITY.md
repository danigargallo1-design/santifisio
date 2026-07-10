# Política de seguridad

## Modelo de amenazas
- Inyecciones (XSS, HTML), CSRF, clickjacking, MITM, scraping abusivo, spam de formulario, secuestro de sesión, fuga de referer, robo de tokens vía `window.opener`.

## Controles aplicados (cliente / servidor web)
- **TLS/HTTPS obligatorio** con HSTS `max-age=2 años; includeSubDomains; preload`.
- **CSP estricta** (`default-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`, `form-action 'self' https://wa.me`, `base-uri 'self'`, `upgrade-insecure-requests`).
- **X-Frame-Options DENY**, **X-Content-Type-Options nosniff**, **Referrer-Policy strict-origin-when-cross-origin**, **Permissions-Policy** restrictiva.
- **COOP/CORP same-origin**, **X-Permitted-Cross-Domain-Policies none**.
- **Hardening del formulario**: sanitización NFKC, filtrado de caracteres de control, validación por regex, honeypot invisible, delay anti-bot (2s), rate-limit por sesión (15s), número WhatsApp fijo en código, `encodeURIComponent`.
- **Enlaces externos**: `rel="noopener noreferrer"`, `window.opener = null`.
- **Bloqueo** de dotfiles, `.env`, `.git`, backups y métodos HTTP no listados.
- **Directorio de índices deshabilitado**, `ServerSignature Off`, cabeceras `Server`/`X-Powered-By` eliminadas.
- **Cifrado en reposo**: recomendado a nivel de hosting (LUKS/BitLocker) y backups cifrados (AES-256).
- **Cookies**: `Secure; SameSite=Strict; HttpOnly` para cookies emitidas por el servidor.

## Buenas prácticas organizativas
- Segregación de entornos: desarrollo / staging / producción con credenciales y dominios distintos.
- Principio de menor privilegio y **RBAC** en panel de hosting y CMS.
- **MFA** obligatoria en cuentas de administración (hosting, DNS, correo, GitHub).
- **Hashing de contraseñas** con Argon2id (o bcrypt cost ≥12) en cualquier backend futuro.
- **Logging y auditoría** de acceso; envío a **SIEM** (p. ej. Wazuh, Elastic SIEM, Graylog).
- **WAF** (Cloudflare / AWS WAF / ModSecurity + OWASP CRS) + **protección DDoS** en el borde.
- **Hardening de servidores**: fail2ban, ufw, kernel actualizado, SSH con claves y sin root.

## Ciclo de seguridad del código
- **SAST**: Semgrep / SonarQube en CI.
- **DAST**: OWASP ZAP baseline en staging.
- **SCA**: `npm audit` / Snyk / Dependabot para dependencias.
- **Pentesting** anual y tras cambios mayores.

## Respuesta ante incidentes
1. Detección (alertas SIEM, monitor uptime, avisos vía `security.txt`).
2. Contención (rotar credenciales, bloquear IP en WAF, activar modo mantenimiento).
3. Erradicación (parcheo, restauración desde backup verificado).
4. Recuperación y post-mortem (RCA, mejora de controles, comunicación a afectados).

Contacto: `seguridad@example.com` — ver `/.well-known/security.txt`.
