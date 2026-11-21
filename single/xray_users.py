"""Pinned Xray HandlerService hot-add; no listener replacement/restart fallback.

v26.3.27 RemoveUser does not terminate the user's established connections, so
revocation deliberately stays on the separately reviewed maintenance path.
"""
import copy,json,re,tempfile
from pathlib import Path

def current(state,runtime):
 if state.get('protocol') not in ('xray','xhttp') or type(state.get('metrics_port')) is not int:return None
 path=runtime.directory(state['protocol'])/'runtime/server.json'
 if not path.is_file() or path.is_symlink():return None
 try:
  config=json.loads(path.read_text());inbound=config['inbounds'][0]
  if 'HandlerService' not in config.get('api',{}).get('services',[]) or inbound.get('tag')!='phone' or inbound.get('protocol')!='vless':return None
  stats=next(i for i in config['inbounds'] if i.get('tag')=='statistics')
  if stats.get('listen')!='127.0.0.1' or stats.get('port')!=state['metrics_port']:return None
  return config
 except (ValueError,KeyError,TypeError,StopIteration):return None

def add(state,user,runtime):
 before=current(state,runtime)
 if before is None:return False
 candidate=runtime.model.xray_server(state,runtime.filtering.load() if state.get('filtering') else None)
 old=copy.deepcopy(before);new=copy.deepcopy(candidate)
 old['inbounds'][0]['settings']['clients']=[];new['inbounds'][0]['settings']['clients']=[]
 if old!=new:return False  # Non-user settings require an explicit maintenance review.
 binary=str(runtime.ROOT/'bin/xray');server='--server=127.0.0.1:'+str(state['metrics_port'])
 payload=copy.deepcopy(candidate);payload['inbounds']=payload['inbounds'][:1]
 payload['inbounds'][0]['settings']['clients']=[u for u in candidate['inbounds'][0]['settings']['clients'] if u['email']==user['login']]
 if len(payload['inbounds'][0]['settings']['clients'])!=1:raise ValueError('The user update is not unique')
 # Persist intended state before a live effect; a lost reply never silently
 # restarts the process. The existing request journal governs remote retries.
 state['pending_user_update']={'operation':'add','login':user['login']};runtime.save(state)
 path=runtime.directory(state['protocol'])/'runtime/server.json';runtime.atomic(path,json.dumps(candidate))
 with tempfile.TemporaryDirectory(dir=runtime.directory(state['protocol'])) as temporary:
  request=Path(temporary)/'users.json';runtime.atomic(request,json.dumps(payload))
  output=runtime.command([binary,'api','adu',server,str(request)],timeout=10)
  # The official CLI can exit zero after adding zero users: check its receipt
  # AND query the actual runtime object, not the process exit code alone.
  if not re.search(r'^Added 1 user\(s\) in total\.$',output,re.M):raise ValueError('Live user addition was not confirmed; inspect this account before retrying')
  actual=json.loads(runtime.command([binary,'api','inbounduser',server,'-tag=phone','-email='+user['login']],timeout=10))
  if not any(u.get('email')==user['login'] for u in actual.get('users',[])):raise ValueError('The running VPN did not confirm the new account')
 state.pop('pending_user_update',None);runtime.save(state);return True
