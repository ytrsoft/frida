import http.client
import json
import hashlib

class MomoGPT:
    def __init__(self):
        self.base_url = 'chatapi.littlewheat.com'
        self.api_key = 'sk-DbtudRCFMS7Fk3uQt0qZJYR6wNhteazpwwWYzOQkimOzo58G'
        self.model = 'gpt-3.5-turbo'
        self.callbacks = {}
        self.history = {}

    def on(self, event: str, callback):
        self.callbacks[event] = callback

    def create_prompt(self, from_id, to_id, content, sex, history):
        gender_map = {0: ["姐妹", "她"], 1: ["兄弟", "他"]}
        title, pronoun = gender_map.get(sex, ["朋友", "TA"])

        prompt = f"""现在你是{title}的真实好友，用{pronoun}常用的说话方式回复一条消息。请遵守以下规则：
                    1. 仅输出1句话，12-18个汉字
                    2. 语气自然，避免AI常见表达
                    3. 根据消息内容关联具体情境

                    对方消息：「{content[-20:]}」
                    立即生成单句回复："""

        return prompt, history

    def post_message(self, message):
        from_id = str(message['from_id'])
        to_id = str(message['to_id'])
        content = message['content']
        sex = message['sex']

        history_key = f"{from_id}_{to_id}"

        if history_key not in self.history:
            self.history[history_key] = []

        prompt_text, self.history[history_key] = self.create_prompt(from_id, to_id, content, sex, self.history[history_key])

        payload = json.dumps({
            'model': self.model,
            'messages': self.history[history_key],
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
                recv = {'from_id': from_id, 'to_id': to_id, 'content': result['choices']['message']['content']}
                self.callbacks['message'](recv)
                self.history[history_key].append({'role': 'assistant', 'content': recv['content']})
        except Exception as e:
            print(f'错误: {e}')
        finally:
            conn.close()
