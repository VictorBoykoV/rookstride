"""Persist deltas per boot and CHILD_SA, with bounded operational history."""
import datetime
import json
import sqlite3
import time
from pathlib import Path


class Ledger:
    def __init__(self, path):
        self.db = sqlite3.connect(str(path), timeout=10)
        self.db.execute("PRAGMA auto_vacuum=INCREMENTAL")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS counters (
                boot TEXT, child TEXT, user TEXT, upload INTEGER, download INTEGER,
                seen REAL, PRIMARY KEY(boot,child));
            CREATE TABLE IF NOT EXISTS daily (
                user TEXT, day TEXT, upload INTEGER DEFAULT 0, download INTEGER DEFAULT 0,
                PRIMARY KEY(user,day));
            CREATE TABLE IF NOT EXISTS history (
                boot TEXT, session TEXT, user TEXT, endpoint TEXT, port INTEGER,
                vpn TEXT, started REAL, seen REAL, active INTEGER,
                PRIMARY KEY(boot,session));
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
        """)

    def sample(self, boot, connections, now=None, complete=True, baseline=False):
        now = time.time() if now is None else now
        day = datetime.datetime.fromtimestamp(now, datetime.timezone.utc).date().isoformat()
        with self.db:
            if complete:
                self.db.execute("UPDATE history SET active=0")
            for c in connections:
                self.db.execute("""INSERT INTO history VALUES(?,?,?,?,?,?,?,?,1)
                    ON CONFLICT(boot,session) DO UPDATE SET endpoint=excluded.endpoint,
                    port=excluded.port,vpn=excluded.vpn,seen=excluded.seen,active=excluded.active""",
                    (boot,c["id"],c["user"],c["endpoint"],c["port"],json.dumps(c["vpn_addresses"]),now-c["age"],now))
                for child in c["children"]:
                    old = self.db.execute("SELECT upload,download,user FROM counters WHERE boot=? AND child=?",(boot,child["id"])).fetchone()
                    if old and old[2] != c["user"]:
                        raise ValueError("A CHILD_SA counter changed owner")
                    du = max(0,child["upload"] - (old[0] if old else 0))
                    dd = max(0,child["download"] - (old[1] if old else 0))
                    if baseline:
                        du = dd = 0
                    if old and (child["upload"] < old[0] or child["download"] < old[1]):
                        # Never count a reset as new traffic under the same SA identity.
                        du = dd = 0
                        self.db.execute("INSERT OR REPLACE INTO meta VALUES('counter_reset',?)",(str(now),))
                    self.db.execute("INSERT OR REPLACE INTO counters VALUES(?,?,?,?,?,?)",(boot,child["id"],c["user"],child["upload"],child["download"],now))
                    if du or dd:
                        self.db.execute("""INSERT INTO daily VALUES(?,?,?,?) ON CONFLICT(user,day)
                            DO UPDATE SET upload=upload+excluded.upload,download=download+excluded.download""",(c["user"],day,du,dd))
            self.db.execute("INSERT OR REPLACE INTO meta VALUES('last_sample',?)",(str(now),))
            self.db.execute("INSERT OR IGNORE INTO meta VALUES('started',?)",(str(now),))

    def disconnect(self, boot, connection, now=None):
        self.sample(boot,[connection],now,complete=False)
        with self.db:
            self.db.execute("UPDATE history SET active=0 WHERE boot=? AND session=?",(boot,connection["id"]))

    def totals(self, month=None):
        month = month or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")
        rows = self.db.execute("SELECT user,SUM(upload),SUM(download) FROM daily WHERE day LIKE ? GROUP BY user",(month+'-%',)).fetchall()
        return [{"user":r[0],"upload":r[1],"download":r[2]} for r in rows]

    def history(self, limit=100):
        return [{"user":u,"endpoint":e,"port":p,"vpn_addresses":json.loads(v),"started":s,"last_seen":l,"active":bool(a)}
                for u,e,p,v,s,l,a in self.db.execute("SELECT user,endpoint,port,vpn,started,seen,active FROM history ORDER BY seen DESC LIMIT ?",(limit,))]

    def prune(self, now=None):
        now=time.time() if now is None else now
        oldest=datetime.datetime.fromtimestamp(now-400*86400,datetime.timezone.utc).date().isoformat()
        with self.db:
            self.db.execute("DELETE FROM counters WHERE seen < ?",(now-30*86400,))
            self.db.execute("DELETE FROM history WHERE active=0 AND seen < ?",(now-30*86400,))
            self.db.execute("DELETE FROM daily WHERE day < ?",(oldest,))
            self.db.execute("DELETE FROM history WHERE active=0 AND rowid NOT IN (SELECT rowid FROM history ORDER BY seen DESC LIMIT 10000)")
        self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.db.execute("PRAGMA incremental_vacuum(500)")

    def metadata(self):
        return dict(self.db.execute("SELECT key,value FROM meta"))

    def close(self):
        self.db.close()
