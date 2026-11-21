"""Password creation policy; authentication of existing accounts is not restricted."""
import json,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'server'))
from rookstride.passwords import validate
from rookstride import admin
class Passwords(unittest.TestCase):
 def test_ike_partial_edit_preserves_labels_kind_and_administrator_generation(self):
  with tempfile.TemporaryDirectory() as d:
   state=Path(d);secret=state/'ipsec.secrets';secret.write_text('fixture : EAP "original secret"\n');original=secret.read_bytes()
   record={'person':'Before','device':'Tablet','kind':'device','administration_account_id':'owned-generation'};(state/'users.json').write_text(json.dumps({'fixture':record}))
   with patch.multiple(admin,STATE=state,SECRETS=secret,PAIR_ROOT=state/'no-pair'),patch.object(admin,'run') as run:
    self.assertTrue(admin.edit_user(dict(login='fixture',person='After'))['edited']);run.assert_not_called()
    self.assertEqual({**record,'person':'After'},admin.catalog()['fixture']);self.assertEqual(original,secret.read_bytes())
    before=(state/'users.json').read_bytes()
    self.assertFalse(admin.edit_user(dict(login='fixture'))['edited']);self.assertEqual(before,(state/'users.json').read_bytes());run.assert_not_called()
 def test_ike_combined_password_patch_and_owner_replace_keep_provenance(self):
  with tempfile.TemporaryDirectory() as d:
   state=Path(d);secret=state/'ipsec.secrets';secret.write_text('fixture : EAP "original secret"\n')
   record={'person':'Before','device':'Tablet','kind':'device','administration_account_id':'owned-generation'};(state/'users.json').write_text(json.dumps({'fixture':record}))
   with patch.multiple(admin,STATE=state,SECRETS=secret,PAIR_ROOT=state/'no-pair'),patch.object(admin,'run') as run:
    self.assertTrue(admin.edit_user(dict(login='fixture',person='After',password=' 1 chosen secret '))['edited'])
    self.assertEqual({**record,'person':'After'},admin.catalog()['fixture']);self.assertIn('" 1 chosen secret "',secret.read_text());run.assert_called_once_with(['ipsec','rereadsecrets'])
    admin.update_user(dict(login='fixture',replace=True,password='next secret'))
    self.assertEqual({**record,'person':'After'},admin.catalog()['fixture']);self.assertNotIn('next secret',(state/'users.json').read_text())
 def test_invalid_ike_combined_patch_leaves_both_files_unchanged(self):
  with tempfile.TemporaryDirectory() as d:
   state=Path(d);secret=state/'ipsec.secrets';secret.write_text('fixture : EAP "original secret"\n');metadata=state/'users.json';metadata.write_text(json.dumps({'fixture':{'person':'Before','device':'Tablet','administration_account_id':'owned-generation'}}));original=(secret.read_bytes(),metadata.read_bytes())
   with patch.multiple(admin,STATE=state,SECRETS=secret,PAIR_ROOT=state/'no-pair'),patch.object(admin,'run') as run:
    for fields in ({'person':'After','device':''},{'person':'After','password':''},{'person':'bad\nlabel','password':'new secret'},{'person':None},{'device':False}):
     with self.assertRaises(ValueError):admin.edit_user(dict(login='fixture',**fields))
     self.assertEqual(original,(secret.read_bytes(),metadata.read_bytes()));run.assert_not_called()
 def test_failed_ike_password_patch_reload_keeps_prior_metadata_and_secret(self):
  with tempfile.TemporaryDirectory() as d:
   state=Path(d);secret=state/'ipsec.secrets';secret.write_text('fixture : EAP "original secret"\n');metadata=state/'users.json';metadata.write_text(json.dumps({'fixture':{'person':'Before','device':'Tablet','administration_account_id':'owned-generation'}}));original=(secret.read_bytes(),metadata.read_bytes())
   with patch.multiple(admin,STATE=state,SECRETS=secret,PAIR_ROOT=state/'no-pair'),patch.object(admin,'run',side_effect=[RuntimeError('fixture reload failure'),None]):
    with self.assertRaises(RuntimeError):admin.edit_user(dict(login='fixture',person='After',password='new secret'))
    self.assertEqual(original,(secret.read_bytes(),metadata.read_bytes()))
 def test_composition_is_optional_and_unicode_counts_as_characters(self):
  for value in ('1','short','a'*64,'a'*127,'abcdefgh','12345678','abcdefghijklmno','"\\!@#$%^&*()','парольёж','😀'*8):self.assertEqual(validate(value),value)
 def test_boundary_controls_and_surrogates_are_rejected(self):
  for value in (None,12,[],True,'','a'*128,'😀'*32,'abc\n12345','abc\r12345','abc\x0012345','abc\u202812345','abc\ud80012345'):
   with self.assertRaises(ValueError):validate(value)
 def test_cli_receives_secret_on_stdin_and_matches_policy(self):
  for value in ('abcdefgh','12345678','"\\!@#$%^&*()','парольёж','😀'*8,'short','a'*16,'abc\n12345'):
   p=subprocess.run([sys.executable,str(ROOT/'server/rookstride/passwords.py')],input=value,text=True,capture_output=True)
   try:validate(value);expected=0
   except ValueError:expected=1
   self.assertEqual(p.returncode,expected);self.assertNotIn(value,p.stdout+p.stderr)

 def test_editing_account_labels_preserves_secret_bytes_and_does_not_reload_ike(self):
  import tempfile,json
  with tempfile.TemporaryDirectory() as d:
   state=Path(d);secret=state/'ipsec.secrets';secret.write_text('fixture : EAP "abcdefgh"\n');original=secret.read_bytes()
   with patch.object(admin,'STATE',state),patch.object(admin,'SECRETS',secret),patch.object(admin,'run') as run:
    result=admin.dispatch(dict(action='edit-user',login='fixture',person='Alex',device='Tablet'))
    self.assertTrue(result['edited']);self.assertEqual(secret.read_bytes(),original);run.assert_not_called()
    self.assertEqual(admin.user_inventory()[0]['device'],'Tablet')
    before=(state/'users.json').read_bytes()
    for req in (dict(login='missing',person='Alex',device='Tablet'),dict(login='fixture',person='',device='Tablet')):
     with self.assertRaises(ValueError):admin.edit_user(req)
    self.assertEqual((state/'users.json').read_bytes(),before)
