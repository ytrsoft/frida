import asyncio
from rpc import rpc
from mq import MQueueManager
from gpt import Message, MomoGPT
from utils import SSEMessage, message_to

def concat(s: str):
    if not s or len(s) < 4:
        return ""
    return f"/{s[:2]}/{s[2:4]}/"

def image(str):
    if not str or len(str) <= 3:
        return ""
    return f"https://img.momocdn.com/album{concat(str)}{str}_L.jpg"

class Dispatcher:
    def __init__(self, maxsize: int):
        self.mq = MQueueManager(maxsize)
        self.momo = rpc()
        self.gpt = MomoGPT()
        self.gpt.on(
          'message',
          lambda message: self.__gpt_message__(message)
        )

    def messages(self):
        if self.mq.rpc_empty():
          return SSEMessage(payload=[])
        else:
          takes = []
          while not self.mq.rpc_empty():
              message = self.mq.rpc_take()
              takes.append(message)
          return SSEMessage(payload=takes)

    def image(self, id):
      return image(id)

    def __rpc_message__(self, body):
      payload = body['payload']
      self.mq.rpc_put(str(payload))
      msg = payload['currentMsg']
      if (msg['mode'] == 1):
        gpt_message = Message(
          momo_id=msg['fromId'],
          remote_id=msg['toId'],
          content=msg['content']
        )
        self.mq.gpt_put(gpt_message)

    def receive(self):
      self.momo.on(
         'message',
         lambda body, _: self.__rpc_message__(body)
      )
      self.momo.exports_sync.receive()

    def post(self, message):
      self.momo.exports_sync.post(message)

    def __gpt_message__(self, message):
      message_to(message)
      self.mq.gpt_running = False

    async def consume(self):
      while True:
        if not self.mq.gpt_empty() and self.mq.gpt_running == False:
            self.mq.gpt_running = True
            message = self.mq.gpt_take()
            self.gpt.post_message(message)
        else:
            await asyncio.sleep(2)

