"""WSC3 line-wrap fix and live calculation capture, Windows desktop UI."""
from __future__ import annotations

import csv
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

from process_patch import attach_game, process_list, CodeNotReady


HOME = Path(sys.executable).resolve().parent if getattr(sys,'frozen',False) else Path(__file__).resolve().parent
LOG_DIR = HOME/'logs'


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


class Worker(threading.Thread):
    def __init__(self,commands,events):
        super().__init__(daemon=True)
        self.commands,self.events=commands,events
        self.session=None
        self.json_file=None; self.csv_file=None; self.csv_writer=None
        self.last_error=None
        self.watching=False
        self.wait_pid=None

    def watch_tick(self):
        games=process_list()
        if not games:
            self.events.put(('waiting','WSC3の起動を待っています。接続後は全体補正ONで記録します。'))
            return
        if len(games)!=1:
            self.watching=False
            raise RuntimeError('WSC3が複数起動しています。1つにしてから起動待ち記録を押してください。')
        pid=games[0]['pid']
        if self.wait_pid!=pid:
            self.close_logs()
            self.open_logs(pid)
            self.wait_pid=pid
            self.log('waiting_for_code',pid=pid)
        try:
            self.session=attach_game(pid,LOG_DIR,1)
        except CodeNotReady:
            self.events.put(('waiting',f'PID {pid}：描画コードの展開待ち。展開後に全体補正・記録を開始します。'))
            return
        self.watching=False
        self.log('attached',mode=1,recovered=self.session.recovered,automatic=True,policy='font_height_plus_one_if_double')
        self.events.put(('connected',{'pid':pid,'mode':1,'recovered':self.session.recovered}))

    def close_logs(self):
        for stream in (self.json_file,self.csv_file):
            if stream:
                stream.close()
        self.json_file=self.csv_file=self.csv_writer=None

    def open_logs(self,pid):
        LOG_DIR.mkdir(parents=True,exist_ok=True)
        stem=datetime.now().strftime('%Y%m%d_%H%M%S_%f')+f'_pid{pid}'
        self.json_file=(LOG_DIR/(stem+'.jsonl')).open('a',encoding='utf-8')
        self.csv_file=(LOG_DIR/(stem+'.csv')).open('w',encoding='utf-8-sig',newline='')
        fields=['collected_at','sequence','thread_id','renderer','original_M','effective_M',
                'quota','rect_width','font_height','line_gap','metrics_height','average_width',
                'original_metrics_max','available_width','hdc','text_address','text_prefix',
                'surface_width','surface_height','renderer_flags']
        self.csv_writer=csv.DictWriter(self.csv_file,fieldnames=fields)
        self.csv_writer.writeheader();self.csv_file.flush()
        self.json_file.write(json.dumps({'event':'session_started','collected_at':utc_now(),'pid':pid,
                                        'note':'Runtime game validation is determined by captured events, not by attach success.'})+'\n')
        self.json_file.flush()
        self.events.put(('log_path',str(self.json_file.name)))

    def log(self,event,**data):
        if self.json_file:
            self.json_file.write(json.dumps({'event':event,'collected_at':utc_now(),**data},ensure_ascii=False)+'\n')
            self.json_file.flush()

    def run(self):
        running=True
        while running:
            try:
                command=self.commands.get(timeout=0.2)
            except queue.Empty:
                command=None
            try:
                if command:
                    name,*args=command
                    if name=='watch':
                        if self.session:
                            raise RuntimeError('先に現在の接続を解除してください。')
                        self.watching=True;self.wait_pid=None
                        self.events.put(('waiting','WSC3の起動を待っています。'))
                    elif name=='connect':
                        if self.session:
                            raise RuntimeError('先に現在の接続を解除してください。')
                        pid,mode=args
                        self.open_logs(pid)
                        self.session=attach_game(pid,LOG_DIR,mode)
                        self.last_error=None
                        self.log('attached',mode=mode,recovered=self.session.recovered,policy='font_height_plus_one_if_double')
                        self.events.put(('connected',{'pid':pid,'mode':mode,'recovered':self.session.recovered}))
                    elif name=='mode':
                        if not self.session:
                            raise RuntimeError('接続されていません。')
                        self.session.set_mode(args[0]);self.log('mode_changed',mode=args[0])
                        self.events.put(('mode',args[0]))
                    elif name in ('detach','stop'):
                        self.watching=False;self.wait_pid=None
                        if self.session:
                            self.session.detach();self.log('detached')
                            self.session=None
                        self.close_logs()
                        self.events.put(('disconnected',None))
                        if name=='stop':
                            running=False;self.events.put(('closed',None))
                if self.watching and not self.session:
                    self.watch_tick()
                if self.session:
                    stats=self.session.poll()
                    if stats['exited']:
                        self.session.detach();self.log('game_exited');self.session=None
                        self.close_logs();self.events.put(('game_exited',None))
                    else:
                        for record in stats['records']:
                            row={'collected_at':utc_now(),**record}
                            self.json_file.write(json.dumps({'event':'calculation',**row},ensure_ascii=False)+'\n')
                            self.csv_writer.writerow(row)
                        if stats['records']:
                            self.json_file.flush();self.csv_file.flush()
                        self.events.put(('stats',stats))
            except Exception as exc:
                self.watching=False
                text=str(exc)
                if command or text!=self.last_error:
                    self.log('error',message=text)
                    self.events.put(('error',text))
                self.last_error=text
                if command and command[0]=='stop':
                    self.events.put(('close_failed',None))
                if not self.session:
                    self.close_logs()


class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('WSC3 全体改行補正・描画計測 v3')
        self.geometry('1080x720');self.minsize(1000,650)
        self.configure(bg='#eef3f7')
        self.option_add('*Font',('Meiryo UI',10))
        style=ttk.Style(self);style.theme_use('clam')
        style.configure('TFrame',background='#eef3f7')
        style.configure('TLabel',background='#eef3f7',foreground='#18334b')
        style.configure('TButton',padding=(12,8))
        style.configure('Title.TLabel',font=('Meiryo UI',18,'bold'))
        style.configure('Hint.TLabel',foreground='#596b7d')
        style.configure('Card.TLabel',background='white',padding=12,font=('Meiryo UI',12))
        self.commands=queue.Queue();self.events=queue.Queue()
        self.worker=Worker(self.commands,self.events);self.worker.start()
        self.connected=False;self.busy=False;self.closing=False;self.processes=[]
        self.waiting=False
        self.status=tk.StringVar(value='未接続：ゲームを起動し、接続するモードを選んでください。')
        self.mode=tk.StringVar(value='未接続')
        self.total=tk.StringVar(value='該当計算 0 回')
        self.fixes=tk.StringVar(value='補正 0 回')
        self.measurement=tk.StringVar(value='幅の値：未取得')
        self.log_path=tk.StringVar(value='接続するとJSONL・CSVを自動保存します。')
        self.notice=tk.StringVar(value='全体補正試用版：文字幅が高さの2倍なら「高さ＋1」へ補正します。大きい文字の補正値は未確認です。')
        self._build()
        self.protocol('WM_DELETE_WINDOW',self.on_close)
        self.refresh()
        self.after(100,self.consume)

    def _build(self):
        panel=ttk.Frame(self,padding=22);panel.pack(fill='both',expand=True)
        ttk.Label(panel,text='WSC3 改行補正・描画計測',style='Title.TLabel').pack(anchor='w')
        ttk.Label(panel,textvariable=self.notice,style='Hint.TLabel').pack(anchor='w',pady=(6,17))
        pick=ttk.Frame(panel);pick.pack(fill='x')
        ttk.Label(pick,text='対象のゲーム').pack(side='left',padx=(0,10))
        self.process_choice=ttk.Combobox(pick,state='readonly',width=60)
        self.process_choice.pack(side='left',fill='x',expand=True)
        self.refresh_button=ttk.Button(pick,text='一覧を更新',command=self.refresh)
        self.refresh_button.pack(side='left',padx=(10,0))
        buttons=ttk.Frame(panel);buttons.pack(fill='x',pady=(12,12))
        self.watch_button=ttk.Button(buttons,text='起動待ちで全体補正',command=self.watch);self.watch_button.pack(side='left',padx=(0,8))
        self.fix_connect=ttk.Button(buttons,text='接続して修正',command=lambda:self.connect(1));self.fix_connect.pack(side='left')
        self.observe_connect=ttk.Button(buttons,text='接続して記録のみ',command=lambda:self.connect(0));self.observe_connect.pack(side='left',padx=8)
        self.enable_button=ttk.Button(buttons,text='修正 ON',command=lambda:self.set_mode(1));self.enable_button.pack(side='left',padx=(14,8))
        self.disable_button=ttk.Button(buttons,text='記録のみ',command=lambda:self.set_mode(0));self.disable_button.pack(side='left')
        self.detach_button=ttk.Button(buttons,text='補正・計測を解除',command=self.detach);self.detach_button.pack(side='right')
        ttk.Label(panel,textvariable=self.status,wraplength=920).pack(anchor='w',pady=(0,12))
        cards=ttk.Frame(panel);cards.pack(fill='x')
        for var in (self.mode,self.total,self.fixes):
            ttk.Label(cards,textvariable=var,style='Card.TLabel').pack(side='left',fill='x',expand=True,padx=(0,8))
        ttk.Label(panel,textvariable=self.measurement,font=('Meiryo UI',12,'bold')).pack(anchor='w',pady=(15,8))
        ttk.Label(panel,text='ゲーム起動前から待機できます。接続完了後の文章計算を記録します。別の描画処理を使う文章は対象外です。',style='Hint.TLabel',wraplength=1000).pack(anchor='w')
        table_frame=ttk.Frame(panel);table_frame.pack(fill='both',expand=True,pady=(12,10))
        self.table=ttk.Treeview(table_frame,columns=('seq','thread','before','after','quota','text'),show='headings',height=9)
        for key,title,width in [('seq','番号',55),('thread','スレッド',75),('before','元の幅',70),('after','使用幅',70),('quota','計算上の字数',100),('text','本文の先頭',460)]:
            self.table.heading(key,text=title);self.table.column(key,width=width,stretch=key=='text')
        self.table.tag_configure('fixed',foreground='#16634b')
        self.table.tag_configure('wide',foreground='#9e3c37')
        bar=ttk.Scrollbar(table_frame,orient='vertical',command=self.table.yview)
        self.table.configure(yscrollcommand=bar.set)
        self.table.pack(side='left',fill='both',expand=True);bar.pack(side='right',fill='y')
        ttk.Label(panel,textvariable=self.log_path,style='Hint.TLabel',wraplength=920).pack(anchor='w')
        footer=ttk.Frame(panel);footer.pack(fill='x',pady=(10,0))
        ttk.Label(footer,text='EXEファイルは変更しません。記録モードも、動作中の描画命令へ計測用中継を入れます。',style='Hint.TLabel',wraplength=740).pack(side='left')
        ttk.Button(footer,text='ログを開く',command=self.open_logs).pack(side='right')
        self.update_buttons()

    def refresh(self):
        if self.connected or self.busy:
            return
        self.processes=process_list()
        self.process_choice['values']=[f"PID {p['pid']}  {p['path']}" for p in self.processes]
        if self.processes:
            self.process_choice.current(0)
            self.status.set('ゲームを検出しました。最初は「接続して記録のみ」でも計算値を取得できます。')
        else:
            self.process_choice.set('wsc3.exe は起動していません')
            self.status.set('未接続：WSC3を起動後、「一覧を更新」を押してください。')
        self.update_buttons()

    def update_buttons(self):
        idle=not self.busy and not self.closing and not self.waiting
        self.watch_button.configure(state='normal' if idle and not self.connected else 'disabled')
        for button in (self.fix_connect,self.observe_connect):
            button.configure(state='normal' if idle and not self.connected and self.processes else 'disabled')
        self.refresh_button.configure(state='normal' if idle and not self.connected else 'disabled')
        for button in (self.enable_button,self.disable_button):
            button.configure(state='normal' if idle and self.connected else 'disabled')
        self.detach_button.configure(state='normal' if not self.closing and not self.busy and (self.connected or self.waiting) else 'disabled')

    def watch(self):
        self.waiting=True;self.update_buttons()
        self.commands.put(('watch',))

    def connect(self,mode):
        index=self.process_choice.current()
        if index<0 or index>=len(self.processes):
            return
        self.busy=True;self.update_buttons();self.status.set('版と描画命令を照合し、接続しています…')
        self.commands.put(('connect',self.processes[index]['pid'],mode))

    def set_mode(self,mode):
        self.busy=True;self.update_buttons();self.commands.put(('mode',mode))

    def detach(self):
        self.busy=True;self.update_buttons();self.status.set('元の描画命令へ戻しています…')
        self.commands.put(('detach',))

    def open_logs(self):
        LOG_DIR.mkdir(parents=True,exist_ok=True)
        os.startfile(str(LOG_DIR))

    def on_close(self):
        if self.closing:
            return
        self.closing=True;self.update_buttons();self.status.set('補正・計測を解除して終了しています…')
        self.commands.put(('stop',))

    def consume(self):
        while True:
            try:
                kind,value=self.events.get_nowait()
            except queue.Empty:
                break
            if kind=='connected':
                self.connected=True;self.busy=False;self.waiting=False
                self.mode.set('修正 ON' if value['mode'] else '記録のみ')
                self.status.set(f"PID {value['pid']} に接続しました。ここから文章の計算を記録します。ゲームを操作してください。")
            elif kind=='waiting':
                self.waiting=True;self.busy=False;self.mode.set('起動・展開待ち')
                self.status.set(value)
            elif kind=='mode':
                self.busy=False;self.mode.set('修正 ON' if value else '記録のみ')
                self.status.set('モードを切り替えました。作戦説明を開き直すと次の計算から反映します。')
            elif kind in ('disconnected','game_exited'):
                self.connected=False;self.busy=False;self.waiting=False;self.mode.set('未接続')
                self.status.set('元の描画命令へ復元しました。' if kind=='disconnected' else 'ゲームが終了したため接続を終了しました。')
            elif kind=='log_path':
                self.log_path.set('ログ：'+value)
            elif kind=='stats':
                self.total.set(f"該当計算 {value['total']} 回")
                self.fixes.set(f"補正 {value['fixes']} 回")
                self.mode.set('修正 ON' if value['mode'] else '記録のみ')
                for r in value['records']:
                    tag='fixed' if r['original_M']!=r['effective_M'] else ('wide' if r['original_M']==24 else '')
                    self.table.insert('',tk.END,values=(r['sequence'],r['thread_id'],r['original_M'],r['effective_M'],r['quota'],r['text_prefix']),tags=(tag,))
                    self.measurement.set(f"実測入力 {r['original_M']} → 使用値 {r['effective_M']} ／ 計算上の基準字数 {r['quota']}")
                children=self.table.get_children()
                for item in children[:-300]:
                    self.table.delete(item)
                if value['records']:
                    self.table.yview_moveto(1)
                if value['lost']:
                    self.status.set(f"計測中：読取前に上書きされた記録 {value['lost']} 件。保存済みログは残っています。")
            elif kind=='error':
                self.busy=False;self.waiting=False;self.status.set('操作を中止：'+value)
            elif kind=='close_failed':
                self.closing=False;self.busy=False
                messagebox.showerror('解除を確認できませんでした','元の命令へ戻したことを確認できないため、画面を開いたままにします。\nゲームを終了してから、このソフトを閉じてください。',parent=self)
            elif kind=='closed':
                self.destroy();return
            self.update_buttons()
        self.after(100,self.consume)


def main():
    try:
        import ctypes
        ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
    except (AttributeError,OSError):
        pass
    app=Application()
    if '--ui-smoke' in sys.argv:
        # App-owned UI exercise only; does not connect to a game.
        app.after(1500,app.on_close)
    else:
        app.after(200,app.watch)
    app.mainloop()


if __name__=='__main__':
    main()
