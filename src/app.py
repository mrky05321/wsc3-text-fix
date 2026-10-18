"""Retired capture UI. The supported executable is the correction-only launcher."""

def main():
    import ctypes
    ctypes.windll.user32.MessageBoxW(None,
        '記録機能は廃止されました。WSC3Launcher.exeを使用してください。',
        'WSC3',0x40)


if __name__=='__main__':
    main()
