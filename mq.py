import asyncio

class MQueueManager:
    def __init__(self, maxsize: int):
        self.rpc = asyncio.Queue(maxsize=maxsize)
        self.gpt = asyncio.Queue(maxsize=maxsize)
        self.gpt_running = False

    def gpt_take(self):
        return self.gpt.get_nowait()

    def gpt_put(self, message):
        self.gpt.put_nowait(message)

    def rpc_take(self):
        return self.rpc.get_nowait()

    def rpc_put(self, message):
        self.rpc.put_nowait(message)

    def rpc_empty(self):
        return self.rpc.empty()

    def gpt_empty(self):
      return self.gpt.empty()
