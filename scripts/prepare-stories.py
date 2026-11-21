#!/usr/bin/env python3
"""Validate and pack the English Persia reader; website archives stay independent."""
import argparse
import json
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SLUG = re.compile(r'^[a-z0-9]+(?:-[a-z0-9]+)*$')


def validate(source):
    """Reject broken panel/caption associations before they reach a release APK."""
    assert not (source / 'catalog.json').is_symlink(), 'Catalog must be a regular source file'
    data = json.loads((source / 'catalog.json').read_text())
    assert data.get('schema') == 1, 'Expected story schema 1'
    world = data['world']
    assert world['id'] == 'persia'
    for key in ('title', 'subtitle', 'seriesTitle', 'description'):
        assert isinstance(world[key], str) and world[key].strip(), 'Missing world ' + key
    assert world['cast'], 'A character reference is required'
    for character in world['cast']:
        assert SLUG.fullmatch(character['id'])
        assert character['name'].strip() and character['description'].strip()
    chapters = data['chapters']
    assert len(chapters) == 2, 'This edition contains exactly two chapters'
    ids = set()
    chapter_ids = set()
    images = []
    for number, chapter in enumerate(chapters, 1):
        assert chapter['number'] == number
        assert SLUG.fullmatch(chapter['id']) and chapter['id'] not in chapter_ids
        chapter_ids.add(chapter['id'])
        for key in ('title', 'summary', 'lesson', 'cliffhanger'):
            assert isinstance(chapter[key], str) and chapter[key].strip(), 'Missing chapter ' + key
        assert len(chapter['pages']) == 10, 'Each chapter needs ten pages'
        for page_number, page in enumerate(chapter['pages'], 1):
            assert page['number'] == page_number
            expected = f'art/ch{number:02d}-p{page_number:02d}.webp'
            assert page['image'] == expected, 'Page image must have an unambiguous ordered filename'
            image = source / expected
            assert image.is_file(), 'Missing optimized artwork: ' + expected
            assert not image.is_symlink() and image.resolve().is_relative_to(source.resolve()), 'Artwork cannot escape the source tree'
            raw = image.read_bytes()
            assert raw[:4] == b'RIFF' and raw[8:12] == b'WEBP', 'Page artwork must be WebP'
            images.append(image)
            assert len(page['panels']) == 6, 'Each page needs six ordered panels'
            for panel in page['panels']:
                assert SLUG.fullmatch(panel['id']) and panel['id'] not in ids
                ids.add(panel['id'])
                assert panel['scene'].strip() and panel['alt'].strip()
                assert isinstance(panel['narration'], str) and isinstance(panel['dialogue'], list)
                assert panel['narration'].strip() or panel['dialogue'], 'A panel needs readable story text'
                for line in panel['dialogue']:
                    assert line['speaker'].strip() and line['text'].strip()
    return data, images


def source_files(source, reader):
    """The complete, explicit runtime edition; authoring masters never enter an APK."""
    data, images = validate(source)
    files = {'catalog.json': source / 'catalog.json'}
    for name in ('index.html', 'reader.css', 'reader.js'):
        path = reader / name
        assert path.is_file() and not path.is_symlink(), 'Missing regular reader source: ' + name
        files[name] = path
    files.update({image.relative_to(source).as_posix(): image for image in images})
    assert len(files) == 24, 'Expected three reader files, one catalog and twenty optimized pages'
    return data, files


def audit_packed(source, reader, destination):
    """Require source parity and reject residual worlds, narration or master images."""
    data, files = source_files(source, reader)
    actual = {path.relative_to(destination).as_posix() for path in destination.rglob('*') if path.is_file()}
    assert actual == set(files), 'Packed story files differ from the current 24-file edition'
    for name, path in files.items():
        target = destination / name
        assert not target.is_symlink() and target.read_bytes() == path.read_bytes(), 'Packed story differs: ' + name
    return data, files


def pack(source, reader, destination):
    data, files = source_files(source, reader)
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    for name, source_file in files.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_file, target)
    return len(data['chapters']), len(files) - 4


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--check-packed', action='store_true', help='With --check, require exact checked-in runtime asset parity')
    args = parser.parse_args()
    source, reader = ROOT / 'stories/persia', ROOT / 'stories/reader'
    if args.check:
        data, images = validate(source)
        if args.check_packed:
            audit_packed(source, reader, ROOT / 'android/overlay/assets/stories')
        print(f"Validated {len(data['chapters'])} chapters, {len(images)} pages, 120 separate panel captions" + ('; exact 24-file runtime parity' if args.check_packed else ''))
    else:
        if args.check_packed:
            parser.error('--check-packed requires --check')
        chapters, pages = pack(source, reader, ROOT / 'android/overlay/assets/stories')
        print(f'Packed Persia: {chapters} chapters, {pages} pages; no historical worlds or audio')
