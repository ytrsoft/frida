import frida

def read_script(name):
    with open(f"{name}.js", 'r', encoding='utf8') as f:
        return f.read()


class Wrap:
    def __init__(self, script):
        self.script = script
        script.load()
        self.rpc = script.exports_sync

    def unload(self):
        self.script.unload()

def create_momo():
    device = frida.get_usb_device()
    session = device.attach('MOMO陌陌')
    code = read_script('rpc')
    script = session.create_script(code)
    return Wrap(script)
