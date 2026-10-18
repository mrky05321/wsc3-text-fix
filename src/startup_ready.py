"""Observe a visible, responsive game window before attaching v0.1.1's hook."""
import ctypes as C
from ctypes import wintypes as W

U=C.WinDLL('user32',use_last_error=True)
CALLBACK=C.WINFUNCTYPE(W.BOOL,W.HWND,W.LPARAM)

def bind(name,result,args):
    function=getattr(U,name)
    function.restype,function.argtypes=result,args
    return function

enum_windows=bind('EnumWindows',W.BOOL,[CALLBACK,W.LPARAM])
window_pid=bind('GetWindowThreadProcessId',W.DWORD,[W.HWND,C.POINTER(W.DWORD)])
visible=bind('IsWindowVisible',W.BOOL,[W.HWND])
iconic=bind('IsIconic',W.BOOL,[W.HWND])
owner=bind('GetWindow',W.HWND,[W.HWND,W.UINT])
client_rect=bind('GetClientRect',W.BOOL,[W.HWND,C.POINTER(W.RECT)])
send_timeout=bind('SendMessageTimeoutW',C.c_ssize_t,
                  [W.HWND,W.UINT,W.WPARAM,W.LPARAM,W.UINT,W.UINT,C.POINTER(C.c_size_t)])


def ready_window(pid):
    """Return a candidate HWND, or None; never suspend or modify a process."""
    found=[]
    @CALLBACK
    def visit(hwnd,_):
        process_id=W.DWORD()
        window_pid(hwnd,C.byref(process_id))
        if process_id.value!=pid or not visible(hwnd) or iconic(hwnd) or owner(hwnd,4):
            return True
        rect=W.RECT()
        if not client_rect(hwnd,C.byref(rect)) or rect.right-rect.left<320 or rect.bottom-rect.top<200:
            return True
        result=C.c_size_t()
        # WM_NULL; abort after 100 ms if the window thread does not respond.
        if send_timeout(hwnd,0,0,0,3,100,C.byref(result)):
            found.append(int(hwnd))
        return True
    if not enum_windows(visit,0):
        raise C.WinError(C.get_last_error())
    return min(found) if found else None


class WindowReadyGate:
    def __init__(self,stable_seconds=2.0):
        self.stable_seconds=stable_seconds
        self.identity=None
        self.since=None

    def update(self,pid,hwnd,now):
        identity=(pid,hwnd) if hwnd else None
        if identity!=self.identity or identity is None:
            self.identity=identity
            self.since=now if identity else None
        return self.since is not None and now-self.since>=self.stable_seconds
