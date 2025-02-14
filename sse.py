import asyncio
from typing import Dict

from fastapi.staticfiles import StaticFiles
from dispatch import Dispatcher
from utils import CORS, load_template

from pathlib import Path
from fastapi import FastAPI
from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi_sse import sse_handler
from contextlib import asynccontextmanager
from fastapi.responses import StreamingResponse
import requests
from io import BytesIO

dispatch = Dispatcher(1024)

dispatch.receive()

@asynccontextmanager
async def lifespan(_):
    task = asyncio.create_task(dispatch.consume())
    try:
        yield
    finally:
        task.cancel()
        await task

app = FastAPI(lifespan=lifespan)
CORS(app)

app.mount('/static', StaticFiles(directory=Path(__file__).parent/'static'), name='static')

@app.get('/sse')
@sse_handler()
async def sse():
    yield dispatch.messages()

@app.get('/', response_class=HTMLResponse)
async def index(request: Request):
    return load_template(request, 'index.html')

@app.post('/post')
async def post(message: Dict):
    dispatch.post(message)
    return message

@app.get('/image/{id}')
async def image(id):
    url = dispatch.image(id)
    response = requests.get(url)
    image_stream = BytesIO(response.content)
    return StreamingResponse(image_stream, media_type="image/jpeg")

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='localhost', port=8082)
