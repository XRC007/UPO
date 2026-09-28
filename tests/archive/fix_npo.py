import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

with open('NPOv2.py', 'r', encoding='utf-8', errors='replace') as f:
    lines = f.readlines()

print('Context around line 1831:')
for i, line in enumerate(lines[1826:1845], start=1827):
    print(f'{i}: {repr(line[:250])}')
