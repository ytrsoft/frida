def concat(s: str):
    if not s or len(s) < 4:
        return ''
    return f'/{s[:2]}/{s[2:4]}/'

def parseImage(str):
    if not str or len(str) <= 3:
        return ''
    return f'https://img.momocdn.com/album{concat(str)}{str}_L.jpg'
