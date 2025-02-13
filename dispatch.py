import asyncio
from rpc import rpc
from mq import MQueueManager
from gpt import Message, MomoGPT
from utils import SSEMessage, load_image, message_to

curr_momoid = '976807129'

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
      result = self.momo.exports_sync.image(id)
      return load_image(result)

    def __rpc_message__(self, body):
      payload = body['payload']
      self.mq.rpc_put(str(payload))
      if 'momoid' in payload:
        from_id = payload['momoid']
        to_id = payload['remoteUser']['momoid']
        if from_id == curr_momoid:
          gpt_message = Message(
            momo_id=from_id,
            remote_id=to_id,
            content=payload['content']
          )
          self.mq.gpt_put(gpt_message)

    def receive(self):
      self.momo.on(
         'message',
         lambda body, _: self.__rpc_message__(body)
      )
      self.momo.exports_sync.receive()

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

