/*
 * MAIN-world passive response observer.
 *
 * Runs at document_start in the page's own JavaScript context, wraps fetch and
 * XMLHttpRequest, and forwards the bodies the page already received to the
 * isolated content script via postMessage. No additional requests are made.
 *
 * Constraints:
 *  - must never alter page behaviour (wrapped functions delegate and always
 *    return the original result; every observer path is try/catch guarded)
 *  - only text-like, 2xx responses, capped at 512 KB
 */
(function () {
  const MAX_BODY_CHARS = 512 * 1024;

  function isInteresting(contentType) {
    if (!contentType) return false;
    if (/(?:text\/html|javascript|text\/css|image\/|audio\/|video\/|font\/|octet-stream)/i.test(contentType)) {
      return false;
    }
    return /(?:json|xml|text\/plain|text\/csv|text\/tab-separated-values|application\/x-www-form-urlencoded)/i.test(
      contentType
    );
  }

  function post(url, contentType, body) {
    if (typeof body !== 'string' || body.length === 0 || body.length > MAX_BODY_CHARS) return;
    try {
      window.postMessage(
        {
          __pss_scan__: true,
          url: typeof url === 'string' ? url : '',
          contentType: typeof contentType === 'string' ? contentType : '',
          body,
        },
        '*'
      );
    } catch (_) {
      /* postMessage unavailable */
    }
  }

  /* ------------------------------------------------------------------ fetch */

  const originalFetch = window.fetch;
  if (typeof originalFetch === 'function') {
    window.fetch = function pssFetch(input, init) {
      const promise = originalFetch.apply(this, arguments);
      try {
        promise
          .then((response) => {
            try {
              if (!response || !response.ok) return;
              const contentType = response.headers.get('content-type') || '';
              if (!isInteresting(contentType)) return;
              const declared = Number(response.headers.get('content-length') || 0);
              if (declared > MAX_BODY_CHARS) return;
              const url =
                response.url ||
                (typeof input === 'string' ? input : input && typeof input.url === 'string' ? input.url : '');
              response
                .clone()
                .text()
                .then((text) => post(url, contentType, text))
                .catch(() => {});
            } catch (_) {
              /* response inspection must never break the page */
            }
          })
          .catch(() => {});
      } catch (_) {
        /* thenable unlikely, but never let the wrapper throw */
      }
      return promise;
    };
  }

  /* -------------------------------------------------------------------- XHR */

  const xhrProto = window.XMLHttpRequest && window.XMLHttpRequest.prototype;
  if (xhrProto && typeof xhrProto.send === 'function') {
    const originalSend = xhrProto.send;
    xhrProto.send = function pssSend() {
      try {
        this.addEventListener('load', () => {
          try {
            if (this.status < 200 || this.status >= 300) return;
            const contentType = this.getResponseHeader('content-type') || '';
            if (!isInteresting(contentType)) return;
            const type = this.responseType;
            let body = null;
            if (type === '' || type === 'text') body = this.responseText;
            else if (type === 'json') body = JSON.stringify(this.response);
            if (typeof body === 'string') post(this.responseURL, contentType, body);
          } catch (_) {
            /* response inspection must never break the page */
          }
        });
      } catch (_) {
        /* addEventListener failure is not fatal */
      }
      return originalSend.apply(this, arguments);
    };
  }
})();
