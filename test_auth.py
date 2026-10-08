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


async def start(locked, verdict):
    a = auth.Auth({"url": "", "token": "", "notify_service": "", "approver_user_id": "", "user": "root"})
    a.connected, a.locked = True, locked
    a.describe = lambda *_: ("polkit", "true", 1)

    async def service(*_):
        pass

    a.service = service
    reader = asyncio.StreamReader()
    task = asyncio.create_task(a.start(0, 0, {}, reader, Writer()))
    await asyncio.sleep(0.01)
    request = a.requests.get(1)
    if not task.done():
        verdict(a, request)
    return await task


def tap_then_approve(a, r):
    a.on_action({"data": {"action": f"HAREMOTE_TAP_{r.nonce}"}, "context": {"user_id": ""}})
    assert not r.verdict.done()
    r.verdict.set_result(True)


async def main():
    approve = lambda a, r: r.verdict.set_result(True)
    assert await start(True, tap_then_approve) is True
    assert await start(False, approve) is False
    assert await start(True, approve) is True
    assert not await start(True, lambda a, r: r.verdict.set_result(False))
    assert not await start(True, lambda a, r: a.abandon())


def lockscreen_key():
    a = auth.Auth({"url": "", "token": "", "notify_service": "", "approver_user_id": "", "user": "root"})
    auth.ancestors = lambda pid: [(9, "pam-helper"), (8, "noctalia"), (7, "noctalia"), (2, "systemd")]
    assert a.describe(9, 0, {"user": "root", "service": "login"})[2] == 7


lockscreen_key()
asyncio.run(main())
print("ok")
