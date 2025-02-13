from rpc import rpc
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from utils import CORS

app = FastAPI()
CORS(app)

momo = rpc()

@app.post('/post')
async def post(request: Request):
    body = await request.json()
    result = momo.exports_sync.post(body)
    return JSONResponse(content=result)

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='localhost', port=8081)
