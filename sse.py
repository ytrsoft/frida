import asyncio
from dispatch import Dispatcher
from utils import CORS, load_template

from fastapi import FastAPI
from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi_sse import sse_handler
from contextlib import asynccontextmanager

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

@app.get('/sse')
@sse_handler()
async def sse():
    yield dispatch.messages()

@app.get('/', response_class=HTMLResponse)
async def index(request: Request):
    return load_template(request, 'index.html')

@app.get('/image/{id}')
async def image(id):
    return dispatch.image(id)

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='localhost', port=8082)
