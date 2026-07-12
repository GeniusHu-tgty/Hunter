(() => {
  const root = window;
  root.__hunterHooks = root.__hunterHooks || {};
  if (root.__hunterHooks.websocket) return;
  root.__hunterHooks.websocket = true;
  root.__hunterWebSockets = root.__hunterWebSockets || [];
  const emit = (record) => console.log("__HUNTER_HOOK__" + JSON.stringify(record));
  const OriginalWebSocket = root.WebSocket;
  function HunterWebSocket(url, protocols) {
    const socket = protocols === undefined
      ? new OriginalWebSocket(url)
      : new OriginalWebSocket(url, protocols);
    root.__hunterWebSockets.push(socket);
    emit({hook: "websocket", phase: "connect", url: String(url).slice(0, 2048)});
    const send = socket.send;
    socket.send = function(data) {
      emit({
        hook: "websocket", direction: "sent",
        dataType: data && data.constructor ? data.constructor.name : typeof data,
        length: typeof data === "string" ? data.length : data && data.byteLength
      });
      return send.apply(this, arguments);
    };
    socket.addEventListener("message", (event) => emit({
      hook: "websocket", direction: "received",
      data: typeof event.data === "string" ? event.data.slice(0, 8192) : undefined,
      dataType: event.data && event.data.constructor ? event.data.constructor.name : typeof event.data,
      length: typeof event.data === "string" ? event.data.length : event.data && event.data.byteLength
    }));
    return socket;
  }
  HunterWebSocket.prototype = OriginalWebSocket.prototype;
  Object.assign(HunterWebSocket, OriginalWebSocket);
  root.WebSocket = HunterWebSocket;
})();
