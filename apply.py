
import subprocess
import argparse
import os

APP_NAME = 'MOMO陌陌'

def get_pid():
    try:
        result = subprocess.run(
            ['frida-ps', '-U'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True
        )
        for line in result.stdout.splitlines():
            columns = line.split()
            if len(columns) >= 2 and APP_NAME.lower() in columns[1].lower():
                return columns[0]
        return None
    except Exception:
        return None

def execute(script):
    pid = get_pid()
    script += '.js'
    script_path = os.path.join(os.getcwd(), script)
    subprocess.run(
        ['frida', '-U', '-p', str(pid), '-l', script_path],
        check=True
    )

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('script')
    args = parser.parse_args()
    execute(args.script)
