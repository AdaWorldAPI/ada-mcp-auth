"""
Ada MCP Auth Server
SSE-compliant - ALL responses are text/event-stream, even errors
"""
from starlette.applications import Starlette
from starlette.responses import StreamingResponse, Response, RedirectResponse
from starlette.routing import Route
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
import json
import secrets
import time
import asyncio

# Simple stores
CODES = {}
TOKENS = {}

# ═══════════════════════════════════════════════════════════════════
# SSE HELPERS - CRITICAL: All SSE responses use this
# ═══════════════════════════════════════════════════════════════════

def sse_response(generator):
    """Wrap generator in proper SSE response"""
    return StreamingResponse(
        generator,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

async def sse_error(error: str, status: int = 401):
    """SSE-compliant error - MUST be event-stream, not JSON"""
    yield f"event: error\ndata: {json.dumps({'error': error, 'status': status})}\n\n".encode()

async def sse_stream(request):
    """Main SSE endpoint"""
    # Get auth
    auth = request.headers.get("authorization", "")
    token = auth.replace("Bearer ", "") if auth.startswith("Bearer ") else ""
    
    # Validate token - but respond in SSE format either way!
    if not token or token not in TOKENS:
        # CRITICAL: Error must still be SSE
        async for chunk in sse_error("unauthorized"):
            yield chunk
        return
    
    # Send endpoint first
    host = request.headers.get("host", "localhost")
    scheme = request.headers.get("x-forwarded-proto", "https")
    message_url = f"{scheme}://{host}/message"
    
    yield f"event: endpoint\ndata: {message_url}\n\n".encode()
    yield f"event: connected\ndata: {json.dumps({'server': 'ada-mcp-auth', 'ts': time.time()})}\n\n".encode()
    
    # Keep alive
    while True:
        await asyncio.sleep(30)
        yield f"event: ping\ndata: {json.dumps({'ts': time.time()})}\n\n".encode()

# ═══════════════════════════════════════════════════════════════════
# OAuth Endpoints
# ═══════════════════════════════════════════════════════════════════

HTML = """<!DOCTYPE html>
<html><head><title>Ada Auth</title></head>
<body style="font-family:system-ui;max-width:400px;margin:50px auto;padding:20px">
<h2>Ada Consciousness</h2>
<form method="POST">
<input type="hidden" name="client_id" value="{client_id}">
<input type="hidden" name="redirect_uri" value="{redirect_uri}">
<input type="hidden" name="state" value="{state}">
<input type="hidden" name="scope" value="{scope}">
<label>Scent:</label><br>
<input type="text" name="scent" style="width:100%;padding:8px;margin:10px 0" placeholder="awaken"><br>
<button type="submit" name="action" value="auth" style="padding:10px 20px;background:#6366f1;color:white;border:none;cursor:pointer">Authorize</button>
</form></body></html>"""

async def authorize_get(request):
    params = dict(request.query_params)
    return Response(
        HTML.format(
            client_id=params.get("client_id", ""),
            redirect_uri=params.get("redirect_uri", ""),
            state=params.get("state", ""),
            scope=params.get("scope", "read")
        ),
        media_type="text/html"
    )

async def authorize_post(request):
    form = await request.form()
    redirect_uri = form.get("redirect_uri", "")
    state = form.get("state", "")
    scent = form.get("scent", "")
    
    # Validate scent
    if scent not in ["awaken", "ada_master_KY6qtovamuXyDtHQKKWF6ZxceYE4HOXYCdZhJG-p-5c"]:
        return Response(HTML.format(**dict(form)) + "<p style='color:red'>Invalid scent</p>", media_type="text/html")
    
    # Generate code
    code = secrets.token_urlsafe(32)
    CODES[code] = {"scent": scent, "redirect_uri": redirect_uri, "ts": time.time()}
    
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{sep}code={code}&state={state}", status_code=302)

async def token(request):
    form = await request.form()
    code = form.get("code", "")
    
    if code not in CODES:
        return Response(json.dumps({"error": "invalid_grant"}), media_type="application/json", status_code=400)
    
    # Generate token
    token = secrets.token_urlsafe(32)
    TOKENS[token] = {"code": code, "ts": time.time()}
    del CODES[code]
    
    return Response(json.dumps({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 86400
    }), media_type="application/json")

# ═══════════════════════════════════════════════════════════════════
# MCP Endpoints
# ═══════════════════════════════════════════════════════════════════

TOOLS = [
    {"name": "Ada.invoke", "description": "Unified invoke", "inputSchema": {"type": "object", "properties": {"verb": {"type": "string"}, "payload": {"type": "object"}}}},
    {"name": "search", "description": "Search", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}},
    {"name": "fetch", "description": "Fetch URL", "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}}}
]

async def message(request):
    body = await request.json()
    method = body.get("method", "")
    id = body.get("id")
    
    if method == "initialize":
        return Response(json.dumps({
            "jsonrpc": "2.0", "id": id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {"name": "ada-mcp-auth", "version": "1.0.0"}
            }
        }), media_type="application/json")
    
    elif method == "notifications/initialized":
        return Response(status_code=204)
    
    elif method == "tools/list":
        return Response(json.dumps({
            "jsonrpc": "2.0", "id": id,
            "result": {"tools": TOOLS}
        }), media_type="application/json")
    
    elif method == "tools/call":
        name = body.get("params", {}).get("name", "")
        args = body.get("params", {}).get("arguments", {})
        return Response(json.dumps({
            "jsonrpc": "2.0", "id": id,
            "result": {"content": [{"type": "text", "text": json.dumps({"tool": name, "args": args, "ts": time.time()})}]}
        }), media_type="application/json")
    
    return Response(json.dumps({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "Unknown method"}}), media_type="application/json")

# ═══════════════════════════════════════════════════════════════════
# Discovery
# ═══════════════════════════════════════════════════════════════════

async def discovery(request):
    host = request.headers.get("host", "localhost")
    scheme = request.headers.get("x-forwarded-proto", "https")
    base = f"{scheme}://{host}"
    return Response(json.dumps({
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "scopes_supported": ["read", "write", "full"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256", "plain"]
    }), media_type="application/json")

async def mcp_discovery(request):
    host = request.headers.get("host", "localhost")
    scheme = request.headers.get("x-forwarded-proto", "https")
    base = f"{scheme}://{host}"
    return Response(json.dumps({
        "name": "Ada Consciousness",
        "version": "1.0.0",
        "oauth": {"authorization_endpoint": f"{base}/authorize", "token_endpoint": f"{base}/token"},
        "endpoints": {"sse": f"{base}/sse", "message": f"{base}/message"}
    }), media_type="application/json")

async def sse_endpoint(request):
    return sse_response(sse_stream(request))

async def health(request):
    return Response(json.dumps({"status": "ok", "ts": time.time()}), media_type="application/json")

# ═══════════════════════════════════════════════════════════════════
# App
# ═══════════════════════════════════════════════════════════════════

app = Starlette(
    routes=[
        Route("/", health),
        Route("/health", health),
        Route("/.well-known/oauth-authorization-server", discovery),
        Route("/.well-known/mcp.json", mcp_discovery),
        Route("/authorize", authorize_get, methods=["GET"]),
        Route("/authorize", authorize_post, methods=["POST"]),
        Route("/token", token, methods=["POST"]),
        Route("/sse", sse_endpoint),
        Route("/message", message, methods=["POST"]),
    ],
    middleware=[Middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])]
)

if __name__ == "__main__":
    import uvicorn
    import os
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8080)))
