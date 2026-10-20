/* CoS secret input - Telegram Mini App.
 * Encrypts the value in the browser and hands only ciphertext to Telegram.WebApp.sendData.
 * Format (base64): 0x01 | RSA-OAEP-SHA256(aesKey) [384 B] | iv [12 B] | AES-256-GCM(JSON {name, nonce, value, ts})
 * No network calls are made by this file. */
'use strict';
(function (root) {
  var PUBLIC_JWK = {"kty":"RSA","alg":"RSA-OAEP-256","ext":true,"key_ops":["encrypt"],"n":"pILgdf0p4t-jgxiGiLAIhgo49UoG4P7rMK29IWiDtPgAcOoosm0GSWuqjLCaeCl_tRtF98UiwQeRQar2GSWAG50sKodTUA6O6-mAJlTPKiSmnOaM3rGg3Kr9m7ePqrhzWtfqeQow9EbVVvu3Lvl7ptGLycPpYhCA_BQ7HlfekId7CKVNfWnw43AqpfYDpgrcKxTrqzLJHQ9IMiIecyZgmfOItS8rS4poNC1nCPdX6qQQFat5fFACXtvfuAdkitB-kTJ-4D6Kinqvg91_Pk8H4iWUif4vfnAufvDbI-M5UcAOijbU1ZPdS7gTpFqGgRCJsGHuKSV-r5AbkEcb5NZL1dZUOuTaxhxstl8Vlx0WuvFja3q0N3LTUxnT7FwWQL5jPP_SxnkB_OrJR-LZMz_QOtR_FtWeBzKkGImy2aA3rG1bBZeJa4YOGCubVjWk24O28oCtyRDlVQ1RNZDBeZnZGPfC-IRBeB1pS6vNmeBmN25DlLWWRvf1uBxSm44_ODEl","e":"AQAB"};
  var NAME_RE = /^[A-Z][A-Z0-9_]{2,63}$/;
  var NONCE_RE = /^[0-9a-f]{32}$/;
  var MAX_SEND = 4096;

  function b64(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return root.btoa(s);
  }

  async function encryptPayload(obj, cryptoImpl) {
    var c = cryptoImpl || root.crypto;
    var subtle = c.subtle;
    var rsa = await subtle.importKey('jwk', PUBLIC_JWK, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
    var aesRaw = c.getRandomValues(new Uint8Array(32));
    var iv = c.getRandomValues(new Uint8Array(12));
    var pt = new root.TextEncoder().encode(JSON.stringify(obj));
    try {
      var aes = await subtle.importKey('raw', aesRaw, { name: 'AES-GCM' }, false, ['encrypt']);
      var ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: iv }, aes, pt));
      var wk = new Uint8Array(await subtle.encrypt({ name: 'RSA-OAEP' }, rsa, aesRaw));
      var out = new Uint8Array(1 + wk.length + iv.length + ct.length);
      out[0] = 1;
      out.set(wk, 1);
      out.set(iv, 1 + wk.length);
      out.set(ct, 1 + wk.length + iv.length);
      return b64(out);
    } finally {
      aesRaw.fill(0);
      pt.fill(0);
    }
  }

  root.CosSecret = { encryptPayload: encryptPayload, NAME_RE: NAME_RE, NONCE_RE: NONCE_RE, MAX_SEND: MAX_SEND };

  if (typeof root.document === 'undefined') return; // loaded in a test harness

  function $(id) { return root.document.getElementById(id); }

  function init() {
    var tg = root.Telegram && root.Telegram.WebApp;
    var q = new root.URLSearchParams(root.location.search);
    var name = q.get('name') || '';
    var nonce = q.get('nonce') || '';
    var label = (q.get('label') || '').slice(0, 200);
    var form = $('f'), input = $('v'), btn = $('b'), msg = $('m');
    $('label').textContent = label || name;
    $('name').textContent = name;
    function diag() { return ' [p=' + (tg && tg.platform) + ' v=' + (tg && tg.version) + ' sd=' + (tg && typeof tg.sendData) + ' n=' + name.length + ' c=' + nonce.length + ']'; }
    function fail(t) { msg.textContent = t + diag(); btn.disabled = true; }
    if (tg) { tg.ready(); tg.expand(); }
    if (!NAME_RE.test(name) || !NONCE_RE.test(nonce)) return fail('Invalid request link. Ask CoS for a new one.');
    if (!tg || typeof tg.sendData !== 'function') return fail('Open this page from the Telegram button.');
    form.addEventListener('submit', async function (ev) {
      ev.preventDefault();
      var value = input.value;
      if (!value) { msg.textContent = 'Enter a value first.'; return; }
      btn.disabled = true;
      msg.textContent = 'Encrypting...';
      try {
        var data = await encryptPayload({ name: name, nonce: nonce, value: value, ts: Date.now() });
        value = null;
        input.value = '';
        if (data.length >= MAX_SEND) { btn.disabled = false; msg.textContent = 'Value too long.'; return; }
        msg.textContent = 'Sending...';
        tg.sendData(data);
      } catch (e) {
        input.value = '';
        btn.disabled = false;
        msg.textContent = 'Encryption failed on this device.';
      }
    });
    msg.textContent = 'Ready.' + diag();
    input.focus();
  }

  if (root.document.readyState === 'loading') root.document.addEventListener('DOMContentLoaded', init);
  else init();
})(typeof window !== 'undefined' ? window : globalThis);
