# cos-secret-input

A tiny static Telegram Mini App for entering one secret value without it ever appearing
as a chat message.

- The page reads `name`, `label` and a one-time `nonce` from the URL.
- The value is encrypted in the browser (WebCrypto: AES-256-GCM, key wrapped with
  RSA-OAEP SHA-256 / 3072-bit) using the public key embedded in `app.js`.
- Only the ciphertext is handed to the bot via `Telegram.WebApp.sendData`.
- No network calls besides loading `telegram-web-app.js`; strict CSP (`connect-src 'none'`).

This repository contains only the public key. The private key never leaves the host.
