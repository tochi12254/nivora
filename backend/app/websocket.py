from fastapi import WebSocket, WebSocketDisconnect

active_connections = []


async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            for conn in active_connections:
                await conn.send_text(data)
    except WebSocketDisconnect:
        active_connections.remove(websocket)
