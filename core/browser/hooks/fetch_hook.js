(() => {
  const root = window;
  root.__hunterHooks = root.__hunterHooks || {};
  if (root.__hunterHooks.fetch) return;
  root.__hunterHooks.fetch = true;
  const emit = (record) => console.log("__HUNTER_HOOK__" + JSON.stringify(record));
  const original = root.fetch;
  root.fetch = async function(input, init) {
    const url = typeof input === "string" ? input : (input && input.url) || "";
    const method = (init && init.method) || (input && input.method) || "GET";
    emit({hook: "fetch", phase: "request", method: String(method), url: String(url).slice(0, 2048)});
    try {
      const response = await original.apply(this, arguments);
      emit({hook: "fetch", phase: "response", url: String(url).slice(0, 2048), status: response.status});
      return response;
    } catch (error) {
      emit({hook: "fetch", phase: "error", url: String(url).slice(0, 2048), message: String(error).slice(0, 2048)});
      throw error;
    }
  };
})();
