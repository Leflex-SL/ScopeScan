"""Bound HTTP bodies before Starlette can spool multipart uploads to disk."""
from starlette.responses import PlainTextResponse


class BodyLimitMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method", "GET") not in {"POST", "PUT", "PATCH"}:
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        limit = (8_000_000 + 65536 if path.startswith(("/software/import", "/api/software/import", "/integrations/import", "/api/integrations/import", "/engines/import", "/api/engines/import")) else 32_000_000 + 65536)
        lengths = [value for key,value in scope.get("headers", []) if key.lower() == b"content-length"]
        if len(lengths) > 1 or lengths and (not lengths[0].isdigit() or len(lengths[0]) > 12 or int(lengths[0]) > limit):
            return await PlainTextResponse("Request body too large or invalid Content-Length", 413)(scope, receive, send)
        size, messages = 0, []
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            size += len(message.get("body", b""))
            if size > limit:
                return await PlainTextResponse("Request body too large", 413)(scope, receive, send)
            messages.append(message)
            if not message.get("more_body", False):
                break
        iterator = iter(messages)
        async def replay_receive():
            try:
                return next(iterator)
            except StopIteration:
                return await receive()
        await self.app(scope, replay_receive, send)
