import http.client
import json

def str_json(data):
    return json.dumps(data, ensure_ascii=False, indent=4)

def create_prompt(from_id, to_id, content, sex, history):
    sex_map = {0: '女生', 1: '男生'}

    if sex == 0:
        tone = '温柔、体贴且幽默的语气回复她，展现出高情商的男人形象'
    elif sex == 1:
        tone = '温柔、体贴且幽默的语气回复他，展现出高情商的女人形象'
    else:
        tone = '用适当的语气回复对方'

    message = {
        'momoid': from_id,
        'remoteId': to_id,
        'content': content
    }

    response = (
        f'我明白了，你现在一定有点难过，'
        f'无论是什么让你感到不开心，我都在这里，愿意倾听和陪伴你。'
        f'其实，生活中的一些小插曲往往是让我们成长的动力，'
        f'即使现在有些困扰，时间会治愈一切的。\n\n'
        f'你不是一个人在经历这一切，我会尽力让你感受到温暖和幽默的力量，'
        f'让我们一起轻松面对挑战，让自己充满正能量。\n\n'
        f'当然，如果你愿意聊更多，我会随时在这里听你倾诉。'
    )

    response = response.replace('难过', '感到有些小困扰')

    response += f'\n\n如果你有任何问题，别犹豫，告诉我哦，我一定会尽力帮忙！'

    history.append({'role': 'user', 'content': content})

    str_json = json.dumps(message, ensure_ascii=False, indent=4)

    prompt = (
        f'以下是{sex_map.get(sex, "男生")}发给我的消息，请你用{tone}，'
        f'请确保回复既安慰对方又带有轻松的幽默感。这里有一个温馨的小提示，'
        f'请用富有同理心的方式回复，并带有一些轻松的语气：\n\n'
        f'{response}\n\n'
        f'---\n'
        f'以下是完整的消息：\n'
        f'{str_json}'
    )

    return prompt, history

def parse_reply_body(message, content):
    message['content'] = content['choices'][0]['message']['content']
    del message['sex']
    return message

class MomoGPT:
    def __init__(self):
        self.base_url = 'chatapi.littlewheat.com'
        self.api_key = 'sk-DbtudRCFMS7Fk3uQt0qZJYR6wNhteazpwwWYzOQkimOzo58G'
        self.model = 'gpt-3.5-turbo'
        self.callbacks = {}
        self.history = {}

    def on(self, event: str, callback):
        self.callbacks[event] = callback

    def post_message(self, message):
        momoid = str(message['momoid'])
        remote_id = str(message['remoteId'])
        content = message['content']
        sex = message['sex']

        history_key = (momoid, remote_id)

        if history_key not in self.history:
            self.history[history_key] = []

        prompt_text, self.history[history_key] = create_prompt(momoid, remote_id, content, sex, self.history[history_key])

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
                recv = parse_reply_body(message, result)
                self.callbacks['message'](recv)
        except Exception as e:
            print(f'错误: {e}')
        finally:
            conn.close()
