import frida

def read_script(name):
    with open(f"{name}.js", 'r', encoding='utf8') as f:
        return f.read()

def rpc():
    device = frida.get_usb_device()
    session = device.attach('MOMO陌陌')
    code = read_script('rpc')
    script = session.create_script(code)
    script.load()
    return script
