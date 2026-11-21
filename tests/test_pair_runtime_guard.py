"""An unresolved engine rollback must survive unrelated pair management."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'single'))
sys.path.insert(0, str(PROJECT / 'server'))
import pair
import user_updates


class PairRuntimeGuardTests(unittest.TestCase):
    def test_pending_update_blocks_new_pair_jobs_before_any_side_effect(self):
        for state in ('prepared', 'preparing', 'applying', 'apply-failed', 'verified', 'rolling-back', 'rollback-failed'):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                folder = root / ('a' * 32)
                folder.mkdir()
                (folder / 'journal.json').write_text(json.dumps({'state': state}))
                original = user_updates.ensure_no_runtime_update
                with patch.object(user_updates, 'ensure_no_runtime_update', side_effect=lambda **kwargs: original(root, **kwargs)), patch.object(pair, 'start') as start:
                    with self.assertRaisesRegex(ValueError, 'Finish or roll back'):
                        pair.dispatch({'command': 'start'})
                    start.assert_not_called()

    def test_terminal_update_does_not_block_a_new_reviewed_pair_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / ('a' * 32)
            folder.mkdir()
            (folder / 'journal.json').write_text(json.dumps({'state': 'accepted'}))
            original = user_updates.ensure_no_runtime_update
            with patch.object(user_updates, 'ensure_no_runtime_update', side_effect=lambda **kwargs: original(root, **kwargs)), patch.object(pair, 'start', return_value={'job': 'b' * 32}) as start:
                request = {'command': 'start'}
                self.assertEqual({'job': 'b' * 32}, pair.dispatch(request))
                start.assert_called_once_with(request)

    def test_progress_remains_readable_during_a_pending_engine_update(self):
        with patch.object(user_updates, 'ensure_no_runtime_update', side_effect=AssertionError('Read must remain available')), patch.object(pair, 'status', return_value={'state': 'paused'}):
            self.assertEqual({'state': 'paused'}, pair.dispatch({'command': 'status', 'job': 'a' * 32}))

    def test_conservative_pause_remains_available(self):
        import native_pair
        manifest = {'version': 2, 'plan': {'pair': 'a' * 32, 'role': 'entry'}}
        with patch.object(user_updates, 'ensure_no_runtime_update', side_effect=AssertionError('Emergency quiesce must remain available')), patch.object(pair, 'load_manifest', return_value=manifest), patch.object(native_pair, 'dispatch', return_value={'paused': True}) as dispatch:
            request = {'command': 'pause', 'pair': 'a' * 32}
            self.assertEqual({'paused': True}, pair.dispatch(request))
            dispatch.assert_called_once_with(request, manifest)


if __name__ == '__main__':
    unittest.main()
