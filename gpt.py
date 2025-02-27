import http.client
import json

class MomoGPT:
    def __init__(self):
        self.base_url = 'chatapi.littlewheat.com'
        self.api_key = 'sk-DbtudRCFMS7Fk3uQt0qZJYR6wNhteazpwwWYzOQkimOzo58G'
        self.model = 'gpt-3.5-turbo'
        self.callbacks = {}
        self.history = {}

    def on(self, event, callback):
        self.callbacks[event] = callback

    def create_prompt(self, content, sex, history):
        gender_map = {0: ['小姐姐', '她'], 1: ['小哥哥', '他']}
        title, pronoun = gender_map.get(sex, ['朋友', '它'])
        if not history or len(history) == 0:
                prompt = f'现在你是{title}的真实好友，用{pronoun}常用的说话方式回复一条消息。请遵守以下规则：\n1. 仅输出1句话，12-18个汉字\n2. 语气自然，避免使用过于正式或模板化的表达，请勿暴露自己AI、人机、助手等行为.\n3. 根据消息内容和上下文关联具体情境\n对方最新消息：「{content}」\n立即生成单句回复：'
        else:
            last_message = history[-1]['content']
            prompt = f'{last_message}\n{pronoun}回复，立即生成单句回复：\n对方最新消息：「{content}」'

        return prompt, history

    def post_message(self, message):
        momoid = str(message['momoid'])
        remote_id = str(message['remoteId'])
        content = message['content']
        sex = message['sex']

        history_key = f'{momoid}_{remote_id}'

        if history_key not in self.history:
            self.history[history_key] = [{'role': 'system', 'content': 'You are a helpful assistant.'}]

        prompt_text, current_history = self.create_prompt(content, sex, self.history[history_key])

        payload = json.dumps({
            'model': self.model,
            'messages': current_history + [{'role': 'user', 'content': prompt_text}],
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

            if 'choices' in result and result['choices']:
                ai_replay = result['choices'][0]['message']['content']
                self.history[history_key].append({'role': 'user', 'content': content})
                self.history[history_key].append({'role': 'assistant', 'content': ai_replay})
                if 'message' in self.callbacks:
                    message['content'] = ai_replay
                    del message['sex']
                    self.callbacks['message'](message)
        except Exception as e:
            print(f'错误: {e}')
        finally:
            conn.close()
