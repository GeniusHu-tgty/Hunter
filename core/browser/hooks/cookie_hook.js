(() => {
  const root = window;
  root.__hunterHooks = root.__hunterHooks || {};
  if (root.__hunterHooks.cookie) return;
  root.__hunterHooks.cookie = true;
  const emit = (record) => console.log("__HUNTER_HOOK__" + JSON.stringify(record));
  const descriptor = Object.getOwnPropertyDescriptor(Document.prototype, "cookie");
  if (!descriptor || !descriptor.get || !descriptor.set) return;
  Object.defineProperty(document, "cookie", {
    configurable: true,
    get() {
      const value = descriptor.get.call(document);
      emit({hook: "cookie", operation: "read", length: value.length});
      return value;
    },
    set(value) {
      const name = String(value).split("=", 1)[0].slice(0, 256);
      emit({hook: "cookie", operation: "write", name, length: String(value).length});
      return descriptor.set.call(document, value);
    }
  });
})();
