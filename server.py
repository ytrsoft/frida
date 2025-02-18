import json
import asyncio
import requests
from utils import parseImage
from io import BytesIO
from pathlib import Path
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from contextlib import asynccontextmanager
from rpc import make_rpc

_rpc = None
msg_mq = asyncio.Queue(maxsize=1024)


def handle_message(message, _):
  payload = message['payload']
  msg_mq.put_nowait(payload)

async def consume():
    global _rpc
    _rpc = make_rpc()
    _rpc.on('message', handle_message)
    _rpc.exports_sync.receive()

@asynccontextmanager
async def lifespan(_):
    task = asyncio.create_task(consume())
    try:
        yield
    finally:
        task.cancel()
        await task

def install():
    instance = FastAPI(lifespan=lifespan)
    instance.add_middleware(
        CORSMiddleware,
        allow_origins=['*'],
        allow_credentials=True,
        allow_methods=['*'],
        allow_headers=['*'],
    )
    instance.mount('/static', StaticFiles(directory=Path(__file__).parent / 'static'), name='static')
    return instance

templates = Jinja2Templates(directory='templates')

app = install()

@app.get('/', response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse('index.html', {'request': request})

@app.get('/image/{id}')
async def image(id):
    url = parseImage(id)
    response = requests.get(url)
    image_stream = BytesIO(response.content)
    return StreamingResponse(image_stream, media_type="image/jpeg")


async def on_rpc(websocket: WebSocket):
  while True:
      takes = []
      while not msg_mq.empty():
        message = await msg_mq.get()
        takes.append(message)
      if takes:
        json_data = json.dumps(takes)
        await websocket.send_text(json_data)
      await asyncio.sleep(1)

@app.websocket("/ws")
async def websocket(websocket: WebSocket):
    await websocket.accept()
    asyncio.create_task(on_rpc(websocket))
    _rpc.exports_sync.init()
    while True:
      data = await websocket.receive_text()
      message = json.loads(data)
      if message['type'] == 2:
          _rpc.exports_sync.post(message['data'])

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='localhost', port=8080)
