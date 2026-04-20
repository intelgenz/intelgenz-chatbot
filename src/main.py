import json
import os
import uuid

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.agent import ask_agent


app = FastAPI(title="Threat Intelligence WebSocket API", version="1.0.0")

allowed_origins = [origin.strip() for origin in os.getenv("ALLOWED_ORIGINS", "*").split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials="*" not in allowed_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ChatRequest(BaseModel):
    message: str
    session_id: str | None = None


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/chat")
async def chat(request: ChatRequest) -> dict[str, str]:
    session_id = request.session_id or str(uuid.uuid4())
    response = await ask_agent(request.message, session_id)
    return {"session_id": session_id, "response": response}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await websocket.accept()
    session_id = websocket.query_params.get("session_id") or str(uuid.uuid4())
    await websocket.send_json({"type": "connected", "session_id": session_id})

    try:
        while True:
            raw_message = await websocket.receive_text()
            try:
                payload = json.loads(raw_message)
                user_message = str(payload.get("message") or payload.get("query") or "").strip()
                session_id = str(payload.get("session_id") or session_id)
            except json.JSONDecodeError:
                user_message = raw_message.strip()

            if not user_message:
                await websocket.send_json(
                    {
                        "type": "error",
                        "session_id": session_id,
                        "response": "Message cannot be empty.",
                    }
                )
                continue

            try:
                response = await ask_agent(user_message, session_id)
                await websocket.send_json(
                    {
                        "type": "response",
                        "session_id": session_id,
                        "response": response,
                    }
                )
            except Exception as exc:
                await websocket.send_json(
                    {
                        "type": "error",
                        "session_id": session_id,
                        "response": f"Unable to process the request: {exc}",
                    }
                )
    except WebSocketDisconnect:
        return
