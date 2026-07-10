/*! security-hardening.js - capa antihacking no intrusiva */
(function () {
  "use strict";

  // 1) Forzar rel seguro en todos los enlaces externos / target=_blank
  function hardenLinks(root) {
    (root || document).querySelectorAll('a[target="_blank"], a[href^="http"]').forEach(function (a) {
      var rel = (a.getAttribute("rel") || "").split(/\s+/).filter(Boolean);
      ["noopener", "noreferrer"].forEach(function (t) {
        if (rel.indexOf(t) === -1) rel.push(t);
      });
      a.setAttribute("rel", rel.join(" "));
      a.addEventListener("click", function () {
        try { if (window.opener) window.opener = null; } catch (e) {}
      }, { passive: true });
    });
  }

  // 2) Sanitización y validación del formulario de contacto
  var WA_NUMBER = "34608973090"; // número fijo, nunca desde el DOM
  var RATE_KEY = "__fw_last_submit";
  var RATE_MS = 15000; // 15s entre envíos

  function nfkc(s) { try { return ("" + s).normalize("NFKC"); } catch (e) { return "" + s; } }
  function stripCtrl(s) { return s.replace(/[\u0000-\u001F\u007F\u200B-\u200F\u2028\u2029]/g, ""); }
  function clean(s, max) { return stripCtrl(nfkc(s)).trim().slice(0, max || 500); }
  function validName(s) { return /^[\p{L} .'\-]{2,60}$/u.test(s); }
  function validPhone(s) { return /^[+0-9 ()\-]{7,20}$/.test(s); }
  function validText(s) { return s.length >= 5 && s.length <= 800; }

  function injectHoneypot(form) {
    if (form.querySelector('[name="website_hp"]')) return;
    var wrap = document.createElement("div");
    wrap.setAttribute("aria-hidden", "true");
    wrap.style.cssText = "position:absolute!important;left:-10000px!important;top:auto!important;width:1px!important;height:1px!important;overflow:hidden!important;";
    wrap.innerHTML = '<label>No rellenar<input type="text" name="website_hp" tabindex="-1" autocomplete="off"></label>';
    form.appendChild(wrap);
    var ts = document.createElement("input");
    ts.type = "hidden"; ts.name = "__ts"; ts.value = String(Date.now());
    form.appendChild(ts);
  }

  function hardenForm(form) {
    if (!form || form.__hardened) return;
    form.__hardened = true;
    form.setAttribute("autocomplete", "off");
    form.setAttribute("novalidate", "novalidate");
    injectHoneypot(form);

    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      ev.stopImmediatePropagation();

      var data = new FormData(form);
      // Honeypot
      if ((data.get("website_hp") || "").toString().length > 0) return;
      // Anti-bot delay (mínimo 2s desde render)
      var ts = parseInt(data.get("__ts") || "0", 10);
      if (!ts || Date.now() - ts < 2000) { alert("Un momento por favor…"); return; }
      // Rate-limit
      try {
        var last = parseInt(sessionStorage.getItem(RATE_KEY) || "0", 10);
        if (Date.now() - last < RATE_MS) { alert("Espera unos segundos antes de reenviar."); return; }
      } catch (e) {}

      var nombre = clean(data.get("nombre") || "", 60);
      var telefono = clean(data.get("telefono") || "", 20);
      var motivo = clean(data.get("motivo") || "", 800);

      if (!validName(nombre)) { alert("Introduce un nombre válido."); return; }
      if (!validPhone(telefono)) { alert("Introduce un teléfono válido."); return; }
      if (!validText(motivo)) { alert("Describe brevemente el motivo (mín. 5 caracteres)."); return; }

      try { sessionStorage.setItem(RATE_KEY, String(Date.now())); } catch (e) {}

      var msg =
        "Hola, quisiera pedir una cita.\n" +
        "Nombre: " + nombre + "\n" +
        "Teléfono: " + telefono + "\n" +
        "Motivo: " + motivo;
      var url = "https://wa.me/" + WA_NUMBER + "?text=" + encodeURIComponent(msg);
      var w = window.open(url, "_blank", "noopener,noreferrer");
      try { if (w) w.opener = null; } catch (e) {}
    }, true); // capture: se ejecuta antes que el handler original
  }

  function init() {
    hardenLinks(document);
    var form = document.getElementById("contact-form");
    if (form) hardenForm(form);
    // Observa cambios (banners de cookies inyectados, etc.)
    try {
      new MutationObserver(function () { hardenLinks(document); }).observe(document.body, { childList: true, subtree: true });
    } catch (e) {}
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
