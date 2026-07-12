(() => {
  const root = window;
  root.__hunterHooks = root.__hunterHooks || {};
  if (root.__hunterHooks.storage) return;
  root.__hunterHooks.storage = true;
  const emit = (record) => console.log("__HUNTER_HOOK__" + JSON.stringify(record));
  ["localStorage", "sessionStorage"].forEach((storageName) => {
    const storage = root[storageName];
    if (!storage) return;
    const proto = Object.getPrototypeOf(storage);
    ["getItem", "setItem", "removeItem", "clear"].forEach((method) => {
      const original = proto[method];
      if (typeof original !== "function" || original.__hunterWrapped) return;
      const wrapped = function(key, value) {
        emit({
          hook: "storage", storage: storageName, method,
          key: key == null ? undefined : String(key).slice(0, 512),
          valueLength: value == null ? undefined : String(value).length
        });
        return original.apply(this, arguments);
      };
      wrapped.__hunterWrapped = true;
      proto[method] = wrapped;
    });
  });
})();
