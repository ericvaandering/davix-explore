#! /usr/bin/env python3
import argparse
import getopt
import gzip
import json
import pdb
import subprocess
import sys
import time
import traceback
from datetime import datetime

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

    good_roots = []
    failed_roots = {}

    ctx = gfal2.creat_context()

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
            failed_roots.update({root: f"Error accessing directory: {e}"})

    return good_roots, failed_roots


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
                  quiet, display_progress, max_scanners, timeout,
                  files_list, compute_empty_dirs, empty_dirs_list, dirs_list,
                  ignore_failed_directories, include_sizes,
                  do_trace):
    n_files = 0
    n_ignored_files = 0
    n_dirs = 0
    n_ignored_dirs = 0
    n_empty_dirs = 0
    total_size = 0

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
    ignore_list = config.IgnoreList
    path_converter = PathConverter(server_root, remove_prefix, add_prefix, root)

    # Use davix-ls in recursive parallel mode
    command = ['davix-ls', '-l', f'-r{max_scanners}', f'davs://{server_root}/{root}']

    # FIXME: This does not worry about the list of all directories since we discard that from the very beginning
    # FIXME: It could be added.

    # Open the process with line buffering enabled and return strings instead of bytes
    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True, bufsize=1) as process:
        for line in process.stdout:  # Stream the output line-by-line as it arrives
            drwx, zero, size, cdate, ctime, path = line.strip().split()

            logpath = path_converter.path_to_logpath(path)

            # The entry is a directory
            if drwx.startswith('d'):
                n_dirs += 1
                if not file_ignored(logpath, ignore_list):
                    if compute_empty_dirs and not int(size):
                        n_empty_dirs += 1
                        if empty_dirs_list is not None:
                            empty_dirs_list.write(logpath + "\n")
                else:
                    n_ignored_dirs += 1

            # The entry is a file
            if drwx.startswith('-'):
                n_files += 1
                if not file_ignored(logpath, ignore_list):
                    total_size += int(size)
                    if files_list is not None:
                        files_list.add(logpath)
                else:
                    n_ignored_files += 1

    # Check if the command executed successfully
    failed = False
    report_error = ''
    if process.returncode != 0:
        report_error = f"Command failed with exit code {process.returncode}"
        failed = True

    t1 = time.time()

    root_stats.update({
        "root_failed": False,
        "error": report_error,
        "failed_subdirectories": -1,
        "files": n_files,
        "directories": n_dirs,
        "empty_directories": n_empty_dirs,
        "directories_ignored": n_ignored_dirs,
        "files_ignored": n_ignored_files,
        "end_time": t1,
        "elapsed_time": t1 - t0,
        "total_size_gb": f'{total_size / 1e9:.1f}',
        "servers": server_root,
        "threads": max_scanners
    })

    del my_stats["scanning"]
    my_stats["roots"].append(root_stats)
    if stats is not None:
        stats[stats_key] = my_stats
        if failed:
            stats["error"] = root_stats.get("error")
    return failed


def main():
    t0 = time.time()

    parser = argparse.ArgumentParser(description="Scan an RSE based on the config file")
    parser.add_argument('-t', '--timeout', type=int, help="Timeout in seconds", default=3600)
    parser.add_argument('-q', '--quiet', help="Quiet mode", action="store_true")
    parser.add_argument('-m', '--max-scanners', type=int, help="Max number of scanners", default=0)
    parser.add_argument('-o', '--output-prefix', type=str, help="Output prefix", default=None)
    parser.add_argument('-n', '--partitions', type=int, help="Number of partitions", default=0)
    parser.add_argument('-c', '--config', help="Config file", metavar="FILE")
    parser.add_argument('-v', '--verbose', help="Verbose mode", action="store_true")
    parser.add_argument('-s', '--stats-file', help="Stats file", metavar="FILE")
    parser.add_argument('-S', '--stats-key', type=str, help="Stats key", default="scanner")
    parser.add_argument('-z', '--zip-out', help="Zip output file(s)", action="store_true")
    parser.add_argument('-k', help='Ignore directory scan errors (not implemented yet)', action="store_true")
    parser.add_argument('-x', '--exclude-file-sizes', help="Exclude file sizes", action="store_true")
    parser.add_argument('-e', '--empty-dirs',
                        help='Empty directory handling ("count-only" to count) or file to write a list ', type=str)
    parser.add_argument('-r', '--root-file-counts', help="Root file counts (not implemented yet)", metavar="FILE",
                        default=None)
    parser.add_argument('-T', '--trace', help='Turn tracing on (not implemented yet)', action="store_true")
    parser.add_argument('rse', type=str, help="RSE nname")
    args = parser.parse_args()

    # Copy to variables we actually use
    rse = args.rse
    config = CEConfiguration(args.config)[rse]
    quiet = args.quiet
    display_progress = not quiet and args.verbose
    max_scanners = args.max_scanners or config.DavsNWorkers
    timeout = args.timeout
    stats_file = args.stats_file
    stats_key = args.stats_key
    ignore_directory_scan_errors = args.k
    stats = None if not stats_file else Stats(stats_file)
    zout = args.zip_out
    do_trace = args.trace
    include_sizes = config.IncludeSizes and not args.exclude_file_sizes

    # Prep the files with expected counts
    # FIXME: Not being used
    root_file_counts = args.root_file_counts
    if root_file_counts:
        root_file_counts = json.load(open(root_file_counts, "r"))
    else:
        root_file_counts = {}

    # Set up the partition files
    nparts = args.partitions or config.NPartitions
    if nparts > 1 and not args.output_prefix:
        print("Output prefix is required for partitioned output")
        parser.print_help(sys.stderr)
        sys.exit(2)
    output = args.output_prefix or "out.list"
    out_list = PartitionedList.create(nparts, output, zout)

    # Compute empty dirs and direct to the right file
    empty_dirs_out = None
    empty_dirs_file = args.empty_dirs
    empty_dirs_count_only = (empty_dirs_file == "count-only")
    if empty_dirs_count_only:
        empty_dirs_file = None
    compute_empty_dirs = bool(empty_dirs_count_only or empty_dirs_file)

    print("Compute empty dirs:", compute_empty_dirs)
    print("Empty dirs output:", "count only" if empty_dirs_count_only else empty_dirs_file)
    # empty_dirs_list = None
    if empty_dirs_file and compute_empty_dirs:
        # empty_dirs_list = []
        if empty_dirs_file.endswith(".gz"):
            empty_dirs_out = gzip.open(empty_dirs_file, "wt")
        else:
            empty_dirs_out = open(empty_dirs_file, "w")

    server = config.DavsServer
    server_root = config.DavsRoot
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

    # root_paths = [canonic_path(root if root.startswith("/") else server_root + "/" + root) for root in config.RootList]

    t0 = time.time()
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

    if not failed:
        all_roots_failed = not good_roots
        print(good_roots)
        for root in good_roots:
            try:
                print(f"Scanning root {root} ...", file=sys.stderr)
                expected = root_file_counts.get(root, 0) > 0

                failed = scan_davs_dir(rse, config, root, expected, my_stats, stats, stats_key,
                                       quiet, display_progress, max_scanners, timeout,
                                       out_list, compute_empty_dirs, empty_dirs_out, None,
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

        # FIXME: Use context managers here
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
