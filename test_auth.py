import asyncio
import importlib.machinery
import importlib.util

loader = importlib.machinery.SourceFileLoader("auth", "ha-remote-auth")
auth = importlib.util.module_from_spec(importlib.util.spec_from_loader("auth", loader))
loader.exec_module(auth)


class Writer:
    def write(self, data):
        pass

    async def drain(self):
        pass


class WS:
    def __init__(self):
        self.sent = []

    async def send_json(self, data):
        self.sent.append(data)


def make(**cfg):
    a = auth.Auth({"url": "", "token": "", "notify_service": "", "approver_user_id": "", "user": "root"} | cfg)
    a.calls = []

    async def service(*args):
        a.calls.append(args)

    a.service = service
    return a


async def start(locked, verdict):
    a = make()
    a.connected, a.locked = True, locked
    a.describe = lambda *_: ("polkit", "true", 1)
    reader = asyncio.StreamReader()
    task = asyncio.create_task(a.start(0, 0, {}, reader, Writer()))
    await asyncio.sleep(0.01)
    request = a.requests.get(1)
    if not task.done():
        verdict(a, request)
    return await task


async def main():
    approve = lambda a, r: r.verdict.set_result(True)
    assert await start(False, approve) is False
    assert await start(True, approve) is True
    assert not await start(True, lambda a, r: r.verdict.set_result(False))
    assert not await start(True, lambda a, r: a.abandon())
    assert not await start(True, deny_while_blocking)
    await resubscribe()
    await expire()
    await rate_limit()
    await policy()


async def resubscribe():
    a = make()
    a.stale = ["ha-remote-old"]
    r = await a.ask("sudo", "true", 1)
    assert r.sub is None
    a.ws = WS()
    await a.on_connect()
    assert a.calls[-1][2]["data"]["tag"] == "ha-remote-old"
    assert a.ws.sent == [{"id": r.sub, "type": "subscribe_events", "event_type": "sudo: true"}]


async def expire():
    a = make(timeout_s=0)
    r = await a.ask("sudo", "true", 1)
    await asyncio.sleep(0.01)
    assert not a.requests and a.calls[-1][2]["data"]["tag"] == a.tag(r)


async def rate_limit():
    a = make()
    assert all([await a.ask("sudo", "true", app) for app in range(auth.RATE_LIMIT)])
    assert await a.ask("sudo", "true", 99) is None


async def policy():
    a = make(policy={"tap": ["lockscreen"], "never": ["^sudo: rm "]})
    assert await a.ask("sudo", "rm -rf /", 1) is None
    assert await a.ask("polkit", "true", 2)
    assert "url" not in a.calls[-1][2]["data"]
    assert await a.ask("lockscreen", "unlock", 3)
    assert "url" in a.calls[-1][2]["data"]


def deny_while_blocking(a, r):
    sent = []
    a.agent = type("Agent", (), {"write": lambda self, data: sent.append(data)})()
    a.on_action({"data": {"action": f"HAREMOTE_DENY_{r.nonce}"}, "context": {"user_id": ""}})
    assert sent == [b'{"type": "polkit", "submit": false}\n']


def lockscreen_key():
    a = auth.Auth({"url": "", "token": "", "notify_service": "", "approver_user_id": "", "user": "root"})
    auth.ancestors = lambda pid: [(9, "pam-helper"), (8, "noctalia"), (7, "noctalia"), (2, "systemd")]
    assert a.describe(9, 0, {"user": "root", "service": "login"})[2] == 7


def tcp_addr():
    assert str(auth.tcp_addr("0100007F:0016")) == "127.0.0.1"
    assert str(auth.tcp_addr("0000000000000000FFFF00000100007F:0016")) == "127.0.0.1"
    assert str(auth.tcp_addr("B80D0120000000000000000001000000:0016")) == "2001:db8::1"


lockscreen_key()
tcp_addr()
asyncio.run(main())
print("ok")
