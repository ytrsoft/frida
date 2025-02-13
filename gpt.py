from dataclasses import dataclass
import http.client
import json
import threading

def str_json(data):
    return json.dumps(data, ensure_ascii=False, indent=4)

def create_prompt(from_id, to_id, content):
    message = {
        'momoid': from_id,
        'remoteId': to_id,
        'content': content
    }
    str_json = json.dumps(message, ensure_ascii=False, indent=4)

    prompt = (
        '以下是女生发给我的消息，请你用温柔、体贴且幽默的语气回复她，'
        '展现出高情商的男人形象。请确保回复既安慰她又带有轻松的幽默感，'
        '以缓解她的情绪。请以纯json格式回复我, 三个字段momoid、remoteId、content：\n'
        f'{str_json}'
    )
    return prompt

def parse_reply_body(body):
    if 'choices' in body and len(body['choices']) > 0:
        reply_content = body['choices'][0]['message']['content']
        reply_content = reply_content.strip('```json\n').strip('```')
        try:
            reply_json = json.loads(reply_content)
            return reply_json
        except json.JSONDecodeError:
            return None
    return None

@dataclass
class Message:
    momo_id: str
    remote_id: str
    content: str

class MomoGPT:
    def __init__(self):
        self.base_url = 'chatapi.littlewheat.com'
        self.api_key = 'sk-DbtudRCFMS7Fk3uQt0qZJYR6wNhteazpwwWYzOQkimOzo58G'
        self.model = 'gpt-3.5-turbo'
        self.callbacks = {}

    def on(self, event: str, callback):
        self.callbacks[event] = callback

    def post_message(self, message: Message):
        momoid = message.momo_id
        remote_id = message.remote_id
        content = message.content
        prompt_text = create_prompt(momoid, remote_id, content)

        payload = json.dumps({
            'model': self.model,
            'messages': [
                {'role': 'user', 'content': prompt_text}
            ],
            'stream': False
        })

        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }

        try:
            conn = http.client.HTTPSConnection(self.base_url)
            conn.request('POST', '/v1/chat/completions', payload, headers)
            res = conn.getresponse()
            data = res.read().decode('utf-8')
            result = json.loads(data)
            if 'message' in self.callbacks:
                recv = parse_reply_body(result)
                self.callbacks['message'](recv)
        except Exception as e:
            print(f'An error occurred: {e}')
        finally:
            conn.close()
