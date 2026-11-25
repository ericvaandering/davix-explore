#! /usr/bin/env python3

import argparse
import queue
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass
from urllib.parse import urlsplit

import requests

DEFAULT_CAPATH = "/cvmfs/grid.cern.ch/etc/grid-security/certificates/"
DAV_NS = "{DAV:}"

PROPFIND_BODY = """<?xml version="1.0" encoding="utf-8" ?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:resourcetype/>
    <D:getcontentlength/>
    <D:getlastmodified/>
  </D:prop>
</D:propfind>"""


def canonic_path(path):
    while path and "//" in path:
        path = path.replace("//", "/")
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    return path


def parent_path(path):
    path = canonic_path(path)
    if path == "/":
        return "/"
    idx = path.rfind("/")
    return path[:idx] if idx > 0 else "/"


def get_token(server_root):
    return subprocess.check_output(['gfal-token', f'davs://{server_root}']).strip().decode('utf-8')


@dataclass
class Entry:
    name: str
    path: str
    is_dir: bool
    size: int
    mtime: str


class Lister:
    def list_directory(self, path):
        """Return every Entry in the subtree under path (not including path itself),
        as reported by one recursive listing call. Raises on error."""
        raise NotImplementedError


class PropfindLister(Lister):

    def __init__(self, server, token, capath=DEFAULT_CAPATH, timeout=300):
        self.server = server
        self.token = token
        self.capath = capath
        self.timeout = timeout

    def list_directory(self, path):
        path = canonic_path(path)
        url = f"https://{self.server}{path}"
        headers = {
            "Depth": "infinity",
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/xml",
        }

        response = requests.request("PROPFIND", url, headers=headers, data=PROPFIND_BODY,
                                    verify=self.capath, timeout=self.timeout)
        response.raise_for_status()

        entries = []
        root = ET.fromstring(response.content)
        for resp in root.findall(f"{DAV_NS}response"):
            href_el = resp.find(f"{DAV_NS}href")
            if href_el is None or not href_el.text:
                continue

            entry_path = canonic_path(urlsplit(href_el.text).path or href_el.text)
            if entry_path == path:
                continue  # this response describes the directory itself, not a child

            is_dir = False
            size = 0
            mtime = None
            for propstat in resp.findall(f"{DAV_NS}propstat"):
                prop = propstat.find(f"{DAV_NS}prop")
                if prop is None:
                    continue

                resourcetype = prop.find(f"{DAV_NS}resourcetype")
                if resourcetype is not None and resourcetype.find(f"{DAV_NS}collection") is not None:
                    is_dir = True

                size_el = prop.find(f"{DAV_NS}getcontentlength")
                if size_el is not None and size_el.text:
                    size = int(size_el.text)

                mtime_el = prop.find(f"{DAV_NS}getlastmodified")
                if mtime_el is not None:
                    mtime = mtime_el.text

            entries.append(Entry(name=entry_path.rsplit("/", 1)[-1], path=entry_path,
                                 is_dir=is_dir, size=size, mtime=mtime))
        return entries


class DavsWalker:

    def __init__(self, lister, nthreads=8, max_retries=3):
        self.lister = lister
        self.nthreads = nthreads
        self.max_retries = max_retries
        self.dir_queue = queue.Queue()  # items: (path, retry_count)
        self.files = []
        self.files_lock = threading.Lock()
        self.confirmed_empty = []
        self.errors = []
        self.errors_lock = threading.Lock()

    def _worker(self):
        while True:
            path, retries = self.dir_queue.get()
            try:
                entries = self.lister.list_directory(path)

                children_of = defaultdict(int)
                for entry in entries:
                    children_of[parent_path(entry.path)] += 1

                if children_of.get(path, 0) == 0:
                    # Nothing came back for the directory we asked about: either it's
                    # genuinely empty, or the server truncated the Depth: infinity response.
                    if retries + 1 >= self.max_retries:
                        with self.errors_lock:
                            self.confirmed_empty.append(path)
                    else:
                        self.dir_queue.put((path, retries + 1))
                else:
                    for entry in entries:
                        if entry.is_dir:
                            if children_of.get(entry.path, 0) == 0:
                                # This nested collection looks empty too -- re-scan it fresh.
                                self.dir_queue.put((entry.path, 0))
                            # else: already fully expanded by this same response
                        else:
                            with self.files_lock:
                                self.files.append(entry)
            except Exception as exc:
                with self.errors_lock:
                    self.errors.append((path, exc))
            finally:
                self.dir_queue.task_done()

    def walk(self, start_path):
        self.dir_queue.put((canonic_path(start_path), 0))
        threads = [threading.Thread(target=self._worker, daemon=True) for _ in range(self.nthreads)]
        for t in threads:
            t.start()
        self.dir_queue.join()
        return self.files, self.confirmed_empty, self.errors


class RecursiveDavsLister:

    def __init__(self, server, root, token, threads=8, max_retries=3, output=None,
                 capath=DEFAULT_CAPATH, timeout=300):
        self.server = server
        self.root = root
        self.output = output
        self.lister = PropfindLister(server, token, capath=capath, timeout=timeout)
        self.walker = DavsWalker(self.lister, nthreads=threads, max_retries=max_retries)
        self._files = []
        self._confirmed_empty = []
        self._errors = []

    def run(self):
        self._files, self._confirmed_empty, self._errors = self.walker.walk(self.root)
        return self

    def files(self):
        return self._files

    def confirmed_empty(self):
        return self._confirmed_empty

    def errors(self):
        return self._errors

    def total_size(self):
        return sum(entry.size for entry in self._files)

    def write_output(self):
        out = open(self.output, "w") if self.output else sys.stdout
        try:
            for entry in self._files:
                print(entry.path, file=out)
        finally:
            if self.output:
                out.close()

    def print_summary(self):
        print(f"Files: {len(self._files)}  Total size: {self.total_size()} bytes", file=sys.stderr)

        if self._confirmed_empty:
            print(f"Confirmed empty directories ({len(self._confirmed_empty)}):", file=sys.stderr)
            for path in self._confirmed_empty:
                print(f"  {path}", file=sys.stderr)

        if self._errors:
            print(f"Errors ({len(self._errors)}):", file=sys.stderr)
            for path, exc in self._errors:
                print(f"  {path}: {exc}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Recursively list a DAVS directory tree")
    parser.add_argument('server', type=str, help="DAVS server, e.g. server.example.com or server.example.com:1094")
    parser.add_argument('root', type=str, help="Root path to scan, e.g. /store/foo")
    parser.add_argument('-t', '--threads', type=int, default=8, help="Number of worker threads")
    parser.add_argument('-r', '--max-retries', type=int, default=3,
                        help="Max consecutive empty results before accepting a directory as empty")
    parser.add_argument('-o', '--output', type=str, default=None, help="File to write file paths to (default stdout)")
    args = parser.parse_args()

    try:
        token = get_token(f"{args.server}{args.root}")
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"Failed to obtain a token via gfal-token: {exc}", file=sys.stderr)
        sys.exit(1)

    if not token:
        print("gfal-token returned an empty token", file=sys.stderr)
        sys.exit(1)

    davs_lister = RecursiveDavsLister(args.server, args.root, token, threads=args.threads,
                                      max_retries=args.max_retries, output=args.output)
    davs_lister.run()
    davs_lister.write_output()
    davs_lister.print_summary()


if __name__ == "__main__":
    main()
