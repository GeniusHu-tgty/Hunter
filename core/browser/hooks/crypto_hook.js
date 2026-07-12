(() => {
  const root = window;
  root.__hunterHooks = root.__hunterHooks || {};
  if (root.__hunterHooks.crypto) return;
  root.__hunterHooks.crypto = true;
  const emit = (record) => console.log("__HUNTER_HOOK__" + JSON.stringify(record));
  const summarize = (value) => ({
    type: value && value.constructor ? value.constructor.name : typeof value,
    length: value && typeof value.length === "number" ? value.length : undefined
  });
  if (root.crypto && root.crypto.subtle) {
    ["encrypt", "decrypt", "digest", "sign", "verify", "deriveBits", "deriveKey", "generateKey", "importKey", "exportKey"].forEach((name) => {
      const original = root.crypto.subtle[name];
      if (typeof original !== "function") return;
      root.crypto.subtle[name] = function(...args) {
        emit({hook: "crypto", api: "subtle", method: name, args: args.map(summarize)});
        return original.apply(this, args);
      };
    });
  }
  if (root.CryptoJS) {
    Object.keys(root.CryptoJS).forEach((name) => {
      const original = root.CryptoJS[name];
      if (typeof original !== "function") return;
      root.CryptoJS[name] = function(...args) {
        emit({hook: "crypto", api: "CryptoJS", method: name, args: args.map(summarize)});
        return original.apply(this, args);
      };
    });
  }
  ["btoa", "atob"].forEach((name) => {
    const original = root[name];
    if (typeof original !== "function") return;
    root[name] = function(value) {
      emit({hook: "crypto", api: "base64", method: name, inputLength: String(value).length});
      return original.apply(this, arguments);
    };
  });
})();
