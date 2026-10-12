"""Local counter collector; no Internet listener or packet inspection."""
import logging
import select
import time
from pathlib import Path
from .usage import Ledger
from .vici import Vici, sessions, connections


def run():
    logging.basicConfig(level=logging.INFO,format="%(asctime)s %(levelname)s %(message)s")
    directory=Path('/var/lib/rookstride')
    directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    ledger=Ledger(directory/'usage.db')
    last_prune=0
    while True:
        try:
            # The daemon PID/start time distinguishes charon restarts within one OS boot.
            pid=int(Path('/var/run/charon.pid').read_text().strip())
            start=Path(f'/proc/{pid}/stat').read_text().split(') ',1)[1].split()[19]
            boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()+':'+str(pid)+':'+start
            with Vici(timeout=5) as stream:
                stream.register('child-updown')
                stream.register('child-rekey')
                metadata=ledger.metadata()
                baseline=not metadata.get('started') or bool(metadata.get('rebase'))
                ledger.sample(boot,connections(sessions()),baseline=baseline)
                with ledger.db:
                    ledger.db.execute("DELETE FROM meta WHERE key='rebase'")
                next_poll=time.monotonic()+30
                while True:
                    if time.monotonic() >= next_poll:
                        ledger.sample(boot,connections(sessions()))
                        next_poll=time.monotonic()+30
                    if time.time()-last_prune > 86400:
                        ledger.prune()
                        last_prune=time.time()
                    ready=[stream.sock] if stream.pending else select.select([stream.sock],[],[],max(0,next_poll-time.monotonic()))[0]
                    if not ready:
                        continue
                    kind,name,event=stream.receive()
                    if kind!=7:
                        continue
                    if name=='child-updown':
                        for c in connections([event],include_deleted=True):
                            if event.get('up')=='yes':
                                ledger.sample(boot,[c],complete=False)
                            else:
                                ledger.disconnect(boot,c)
                    elif name=='child-rekey':
                        # Final old-generation counters are distinct from the new generation.
                        for n,ike in event.items():
                            if not isinstance(ike,dict): continue
                            for child in list(ike.get('child-sas',{}).values()):
                                if not isinstance(child,dict): continue
                                for generation in ('old','new'):
                                    if generation not in child: continue
                                    copy=dict(ike); copy['child-sas']={'child':child[generation]}
                                    ledger.sample(boot,connections([{n:copy}],include_deleted=True),complete=False)
        except (OSError,ValueError,RuntimeError,ConnectionError) as exc:
            logging.warning('Monitoring unavailable (%s); retrying in 5 seconds',type(exc).__name__)
            # Persist a visible coverage gap. A poll cannot recover a tunnel removed during an outage.
            with ledger.db:
                ledger.db.execute("INSERT OR REPLACE INTO meta VALUES('gap',?)",(str(time.time()),))
            time.sleep(5)


if __name__=='__main__':
    run()
