#! /usr/bin/env python3

import getopt
import gzip
import json
import pdb
import re
import sys
import time
import traceback
from datetime import datetime
from hashlib import md5
import subprocess
import gfal2

# from pythreader import TaskQueue, Task, DEQueue, PyThread, synchronized, ShellCommand, Primitive
from rucio_consistency import Stats, PartitionedList, CEConfiguration

# from rucio_consistency.xrootd import XRootDClient

Version = "1.0.0"

GB = 1024 * 1024 * 1024

try:
    import tqdm

    Use_tqdm = True
except:
    Use_tqdm = False


# FIXME: Do I need this
# def truncated_path(root, path):
#     if path == root:
#         return "/"
#     relpath = path
#     if path.startswith(root + "/"):
#         relpath = path[len(root) + 1:]
#     N = 5
#     parts = relpath.split("/")
#     while parts and not parts[0]:
#         parts = parts[1:]
#     if len(parts) <= N:
#         # return "%s -> %s" % (path, relpath)
#         return relpath
#     else:
#         n = len(parts)
#         # return ("%s -> ..(%d)../" % (path, n-N))+"/".join(parts[-N:])
#         return ("..(%d)../" % (n - N)) + "/".join(parts[-N:])


# FIXME: Do I need this
def canonic_path(path):
    while path and "//" in path:
        path = path.replace("//", "/")
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    return path


# FIXME: Do I need this
# def relative_path(root, path):
#     # returns part relative to the root. Returned relative path does NOT have leading slash
#     # if the argument path does not start with root, returns the path unchanged
#     path = canonic_path(path)
#     if path.startswith(root + "/"):
#         path = path[len(root) + 1:]
#     return path


# FIXME: Do I need this
class PathConverter(object):

    def __init__(self, site_prefix, remove_prefix, add_prefix, root):
        self.SitePrefix = site_prefix
        self.RemovePrefix = remove_prefix
        self.AddPrefix = add_prefix
        self.Root = root

    def path_to_logpath(self, path):
        # convert physical path after site prefix to LFN space by applying RemovePrefix and AddPrefix if any
        # for CMS, this is a no-op as of now

        path = canonic_path(path)
        assert path.startswith('/'), f"Expected input path to start with /: {path}"
        if self.RemovePrefix and path.startswith(self.RemovePrefix):
            path = path[len(self.RemovePrefix):]

        if self.AddPrefix:
            path = self.AddPrefix + path

        return canonic_path(path)


def validate_roots(server, server_root, root_list, timeout):
    """
    Validate which roots a DAVS server has to be scanned

    :param server:
    :param server_root:
    :param root_list:
    :param timeout:
    :return:
    """

    # pdb.set_trace()
    good_roots = []
    failed_roots = {}

    ctx = gfal2.creat_context()

    # 2. Target URL (e.g., a WebDAV or S3 endpoint)
    for root in root_list:
        url = f"davs://{server}{server_root}{root}"

        try:
            # 3. Retrieve metadata for the remote file
            print(f"Checking for: {root}")
            stat_info = ctx.stat(url)

            print(f" Found: {root}")
            good_roots.append(root)
        except Exception as e:
            print(f" Missing: {root}")
            failed_roots.update({root: f"Error accessing file: {e}"})
    print(good_roots, failed_roots)
    return good_roots, failed_roots


Usage = """
python xrootd_scanner.py [options] <rse>
    Options:
    -c <config.yaml>|-c rucio   - required - read config either from a YAML file or from Rucio
    -o <output file prefix>     - output will be sent to <output>.00000, <output>.00001, ...
    -t <timeout>                - xrdfs ls operation timeout (default 30 seconds)
    -m <max workers>            - default 5
    -R <recursion depth>        - start using -R at or below this depth (dfault 3)
    -n <nparts>
    -k                          - do not treat individual directories scan errors as overall scan failure
    -q                          - quiet - only print summary
    -x                          - do not use metadata (ls -l), do not include file sizes
    -M <max_files>              - stop scanning the root after so many files were found
    -s <stats_file>             - write final statistics to JSON file
    -r <root count file>        - JSON file with file counds by root
    -E <n>                      - compile empty directories only event n-th day. n > 0
    -e <path>                   - output file for empty dits list. Use .gz extension to have it compressed
    -e count-only               - do not produce empty dirs list, just count them
    -T                          - turn tracing on
"""


# FIXME: Do I need this
def path_to_lfn(path, path_prefix, remove_prefix, add_prefix, path_filter, rewrite_path, rewrite_out):
    # convert absoulte physical path, which starts with path_prefix to LFN
    # for CMS, path may look like /eos/cms/tier0/store/root/path/file
    # after removing the <path_prefix>, then <remove_prefix> and adding <add_prefix> it will look like /store/root/path/file

    assert path.startswith(path_prefix)

    lfn = "/" + path[len(path_prefix):]

    if remove_prefix and lfn.startswith(remove_prefix):
        lfn = lfn[len(remove_prefix):]

    if add_prefix:
        lfn = add_prefix + lfn

    if path_filter:
        if not path_filter.search(lfn):
            return None

    if rewrite_path is not None:
        if not rewrite_path.search(lfn):
            sys.stderr.write(f"Path rewrite pattern for root {path_prefix} did not find a match in path {lfn}\n")
            sys.exit(1)
        lfn = rewrite_path.sub(rewrite_out, lfn)
    return lfn


def file_ignored(logpath, ignore_list):
    return any(logpath.startswith(subdir) for subdir in ignore_list) or logpath in ignore_list


def scan_davs_dir(rse, config, root, root_expected, my_stats, stats, stats_key,
                  quiet, display_progress, max_files,
                  max_scanners, timeout,
                  files_list, compute_empty_dirs, empty_dirs_list, dirs_list,
                  ignore_failed_directories, include_sizes,
                  do_trace):
    max_scanners = 32
    n_files = 0
    n_ignored_files = 0
    n_empty_dirs = 0

    ignore_list = config.IgnoreList

    files = None
    dirs = []
    # empty_dirs = []

    t0 = time.time()
    root_stats = {
        "root": root,
        "expected": root_expected,
        "start_time": t0,
        "timeout": timeout,
        "max_scanners": max_scanners,
        # "servers": client.Servers
    }

    my_stats["scanning"] = root_stats
    if stats is not None:
        stats.update_section(stats_key, my_stats)

    remove_prefix = config.RemovePrefix
    add_prefix = config.AddPrefix
    server_root = config.DavsServer
    path_converter = PathConverter(server_root, remove_prefix, add_prefix, root)

    # Use davix-ls in recursive parallel mode
    command = ['davix-ls', '-l', f'-r{max_scanners}', f'davs://{server_root}/{root}']
    pdb.set_trace()
    # Open the process with line buffering enabled and return strings instead of bytes
    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True, bufsize=1) as process:
        for line in process.stdout:  # Stream the output line-by-line as it arrives
            drwx, zero, size, cdate, ctime, path = line.strip().split()

            logpath = path_converter.path_to_logpath(path)

            # The entry is a directory
            if compute_empty_dirs and drwx.startswith('d'):
                if dirs_list is not None:
                    dirs_list.append(logpath)
                if not int(size):
                    n_empty_dirs += 1
                    if empty_dirs_list is not None:
                        empty_dirs_list.append(logpath)

            # The entry is a file
            if drwx.startswith('-'):
                n_files += 1
                pdb.set_trace()
                if not file_ignored(logpath, ignore_list):
                    if files_list is not None:
                        files_list.add(logpath)
                else:
                    n_ignored_files += 1

    # Check if the command executed successfully
    if process.returncode != 0:
        print(f"\nCommand failed with exit code {process.returncode}")
        return "failed", None, None, None, process.stderr

    return "done", dirs, files, empty_dirs_list, None


def main():
    t0 = time.time()
    opts, args = getopt.getopt(sys.argv[1:], "t:m:o:R:n:c:vqM:s:S:zkxe:r:E:T")
    opts = dict(opts)

    if len(args) != 1 or not "-c" in opts:
        print("Version:", Version)
        print(Usage)
        sys.exit(2)

    rse = args[0]
    config = CEConfiguration(opts["-c"])[rse]

    quiet = "-q" in opts
    display_progress = not quiet and "-v" in opts
    max_files = int(opts.get("-M", 0)) or None

    # recursive_threshold = int(opts.get("-R", config.RecursionThreshold))
    max_scanners = int(opts.get("-m", config.DavsNWorkers))
    timeout = int(opts.get("-t", config.DavsTimeout))

    stats_file = opts.get("-s")
    stats_key = opts.get("-S", "scanner")
    ignore_directory_scan_errors = "-k" in opts
    root_file_counts = opts.get("-r")
    if root_file_counts:
        root_file_counts = json.load(open(root_file_counts, "r"))
    else:
        root_file_counts = {}

    stats = None if not stats_file else Stats(stats_file)

    zout = "-z" in opts
    do_trace = "-T" in opts

    if "-n" in opts:
        nparts = int(opts["-n"])
    else:
        nparts = config.NPartitions

    if nparts > 1:
        if not "-o" in opts:
            print("Output prefix is required for partitioned output")
            print(Usage)
            sys.exit(2)

    output = opts.get("-o", "out.list")

    out_list = PartitionedList.create(nparts, output, zout)

    #
    # Do we need to compute empty dirs ?
    #
    empty_dirs_out = None
    empty_dirs_file = opts.get("-e")
    empty_dirs_count_only = empty_dirs_file == "count-only"
    if empty_dirs_count_only:
        empty_dirs_file = None
    compute_empty_dirs = bool(empty_dirs_count_only or empty_dirs_file)
    if compute_empty_dirs and "-E" in opts:
        modulo = int(opts["-E"])
        assert modulo != 0
        rse_hash = int.from_bytes(md5(rse.encode("utf-8")).digest(), byteorder='big')
        day_number = int(time.time() / (24 * 3600))
        compute_empty_dirs = (day_number % modulo) == (rse_hash % modulo)
        if not compute_empty_dirs:
            print("Empty directories list will not be computed because the day does not match the -E option value")

    print("Compute empty dirs:", compute_empty_dirs)
    print("Empty dirs outut:", "count only" if empty_dirs_count_only else empty_dirs_file)
    empty_dirs_list = None
    if empty_dirs_file and compute_empty_dirs:
        empty_dirs_list = []
        if empty_dirs_file.endswith(".gz"):
            empty_dirs_out = gzip.open(empty_dirs_file, "wt")
        else:
            empty_dirs_out = open(empty_dirs_file, "w")

    server = config.DavsServer
    server_root = config.DavsRoot
    include_sizes = config.IncludeSizes and not "-x" in opts
    if not server_root or not server:
        print(f"Server or server root is not defined for {rse} using DAVS. Should be defined as 'server_root'")
        sys.exit(2)

    t = time.time()
    my_stats = {
        "rse": rse,
        "scanner": {
            "type": "davs",
            "version": Version
        },
        "parallel_scanners": max_scanners,
        "server_root": server_root,
        "server": server,
        "roots": [],
        "start_time": t,
        "end_time": None,
        "status": "started",
        "files_output_prefix": output,
        "empty_dirs_output_file": empty_dirs_file,
        "compute_empty_dirs": compute_empty_dirs,
        "empty_dirs_count_only": empty_dirs_count_only,
        "heartbeat": t,
        "heartbeat_utc": datetime.utcfromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S UTC")
    }

    if stats is not None:
        stats[stats_key] = my_stats

    root_paths = [canonic_path(root if root.startswith("/") else server_root + "/" + root) for root in config.RootList]

    # import pdb; pdb.set_trace()

    t0 = time.time()
    # This is where the meat starts
    good_roots, failed_roots = validate_roots(server, server_root, config.RootList, timeout)
    t1 = time.time()

    failed = False
    my_stats["roots"] = my_stats_roots = []
    for root, error in failed_roots.items():
        expected = root_file_counts.get(root, 0) > 0
        my_stats_roots.append({
            "root": root,
            "expected": expected,
            "start_time": t0,
            "timeout": timeout,
            "root_failed": True,
            "error": error,
            "end_time": t1,
            "files": 0,
            "directories": 0,
            "elapsed_time": t1 - t0
        })
        failed = failed or expected

    pdb.set_trace()

    if not failed:
        all_roots_failed = not good_roots
        for root in good_roots:
            try:
                print(f"Scanning root {root} ...", file=sys.stderr)
                expected = root_file_counts.get(root, 0) > 0
                # FIXME: We need to write out the empty directories
                failed = scan_davs_dir(rse, config, root, expected, my_stats, stats, stats_key,
                                       quiet, display_progress, max_files,
                                       max_scanners, timeout,
                                       out_list, compute_empty_dirs, empty_dirs_list, None,
                                       ignore_directory_scan_errors, include_sizes, do_trace)

            except:
                exc = traceback.format_exc()
                print(exc)
                lines = exc.split("\n")
                scanning = my_stats.setdefault("scanning", {"root": root})
                scanning["exception"] = lines
                scanning["exception_time"] = time.time()
                failed = True

            if failed:
                break

        # FIXME: Use a context manager here
        out_list.close()
        if empty_dirs_out is not None:
            empty_dirs_out.close()

        total_files = sum(root_stats["files"] for root_stats in my_stats["roots"])

    if failed or all_roots_failed or total_files == 0:
        my_stats["status"] = "failed"
    else:
        my_stats["status"] = "done"

    my_stats["end_time"] = t1 = time.time()
    my_stats["elapsed"] = t1 - my_stats["start_time"]
    if stats is not None:
        stats[stats_key] = my_stats

    if failed or all_roots_failed:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
