#!/usr/bin/env python3
"""Drive the live TUI in a pseudo-terminal, send keystrokes, and dump the first full frame
with ANSI colours stripped. Usage: tui_drive.py <cols> <rows> <keys-after-seconds> -- <cmd...>"""
import os, pty, re, select, struct, sys, termios, fcntl, time, signal

cols, rows, wait = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
cmd = sys.argv[sys.argv.index('--') + 1:]
keys = os.environ.get('KEYS', 'q').encode().decode('unicode_escape').encode('latin1')

pid, fd = pty.fork()
if pid == 0:
    os.environ['TERM'] = 'xterm-256color'; os.environ['COLORTERM'] = 'truecolor'
    os.execvp(cmd[0], cmd)
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))
out = b''
t0 = time.time(); sent = False; done = False
while not done:
    r, _, _ = select.select([fd], [], [], 0.1)
    if r:
        try:
            chunk = os.read(fd, 65536)
            if not chunk: break
            out += chunk
        except OSError: break
    if not sent and time.time() - t0 > wait:
        # Interleave reads while typing so the child never blocks on a full pty buffer.
        tokens = re.findall(rb'\x1b\[[0-9;]*[A-Za-z~]|.', keys, re.S)
        for k in tokens:
            os.write(fd, k)
            end = time.time() + 0.25
            while time.time() < end:
                r, _, _ = select.select([fd], [], [], 0.05)
                if r:
                    try: out += os.read(fd, 65536)
                    except OSError: break
        sent = True
    if time.time() - t0 > wait + 8: os.kill(pid, signal.SIGTERM); break
deadline = time.time() + 4
while True:
    wpid, status = os.waitpid(pid, os.WNOHANG)
    if wpid: break
    if time.time() > deadline: os.kill(pid, signal.SIGKILL); wpid, status = os.waitpid(pid, 0); print('HUNG: had to SIGKILL'); break
    try:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r: out += os.read(fd, 65536)
    except OSError: pass
text = out.decode('utf-8', 'replace')
print('exit status:', os.waitstatus_to_exitcode(status), '| bytes:', len(out), '| alt screen enter/exit:', '\x1b[?1049h' in text, '\x1b[?1049l' in text)
# Reconstruct the last drawn state of each row
rows_map = {}
for m in re.finditer(r'\x1b\[(\d+);1H(.*?)\x1b\[K', text, re.S):
    rows_map[int(m.group(1))] = re.sub(r'\x1b\[[0-9;?]*[A-Za-z]', '', m.group(2))
for i in range(1, max(rows_map) + 1 if rows_map else 0):
    print(rows_map.get(i, ''))
