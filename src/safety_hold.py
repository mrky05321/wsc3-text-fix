"""Runtime and packaging hold following the 2026-10-18 host-freeze report."""

RUNTIME_APPROVED = False
HOLD_MESSAGE = (
    'この開発版はPCフリーズの報告により使用停止中です。'
    'ゲームの起動・接続・メモリ変更は行いません。'
    '原因調査と実機での検証が完了するまで使用しないでください。'
)


def require_runtime_approval():
    if not RUNTIME_APPROVED:
        raise RuntimeError(HOLD_MESSAGE)
