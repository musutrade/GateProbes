#!/usr/bin/env python3
"""Accept the unpublished flat source-risk PR package after clean extraction.

The inherited package filename/version does not identify a published artifact.
No tag/release action or modification to the immutable 0.2 default gate occurs.
"""
import argparse
from pathlib import Path
from package_plugin import accept_rust_archive

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--consumer', type=Path, required=True)
    parser.add_argument('--core-root', type=Path, required=True)
    args = parser.parse_args()
    accept_rust_archive(args.archive.resolve(), args.source.resolve(), args.consumer.resolve(),
                        args.core_root.resolve(), flat=True)
