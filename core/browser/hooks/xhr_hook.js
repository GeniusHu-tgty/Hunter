(() => {
  const root = window;
  root.__hunterHooks = root.__hunterHooks || {};
  if (root.__hunterHooks.xhr) return;
  root.__hunterHooks.xhr = true;
  const emit = (record) => console.log("__HUNTER_HOOK__" + JSON.stringify(record));
  const Open = XMLHttpRequest.prototype.open;
  const Send = XMLHttpRequest.prototype.send;
  const SetHeader = XMLHttpRequest.prototype.setRequestHeader;
  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    this.__hunterXhr = {method: String(method), url: String(url), headers: {}};
    emit({hook: "xhr", phase: "open", method: String(method), url: String(url).slice(0, 2048)});
    return Open.call(this, method, url, ...rest);
  };
  XMLHttpRequest.prototype.setRequestHeader = function(name, value) {
    if (this.__hunterXhr) this.__hunterXhr.headers[String(name)] = String(value).slice(0, 2048);
    return SetHeader.call(this, name, value);
  };
  XMLHttpRequest.prototype.send = function(body) {
    const meta = this.__hunterXhr || {};
    emit({hook: "xhr", phase: "request", method: meta.method, url: meta.url, bodyType: typeof body});
    this.addEventListener("loadend", () => emit({
      hook: "xhr", phase: "response", url: meta.url, status: this.status,
      responseType: this.responseType || "text"
    }), {once: true});
    return Send.call(this, body);
  };
})();
