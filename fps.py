#!/usr/bin/python3
#
# Copyright (C) 2021 The Android Open-Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Comments and code based on:
# https://chromium.googlesource.com/chromium/src/build/+/689a0a184e54c7a50a05964ae666b82e96ea549f/android/pylib/perf/surface_stats_collector.py

"""Retrieves average FPS and latencies for the target package-name.

Provides refresh rate, total frames, average FPS, and statistics for frame
latencies such as mean, standard deviation, min and max.

To run this script with the CLI:
Syntax:
python3 fps.py [-h] [-d DURATION] [--dump FILENAME] [-l | --print_latency |
--no-print_latency] [-f] package_name

Arguments:
    package_id: (Required) Package name of the application.
    duration or d: (optional) Duration of time we run this script. By default
                the duration is 1 day.
    dump or o: (Optional) File name where stats are stored.
    print_latency or l: (Optional|Experimental) Displays latencies of the last
        120 frames. provide this argument if you want to display the latencies.
    full or f: (Optional) A boolean indicating if we like to skip the partial
        name or not. We have to input full package when this argument is passed.

Example:
    - python3 fps.py -d 30 -o example.txt com.example.app -l
    - python3 fps.py --duration 30 --dump example.txt com.example.app
        --print_latency
"""

import argparse
import dataclasses
import datetime
import itertools
import logging
import re
import signal
import statistics
import subprocess
import sys
import time
from typing import List

# ADB command to get the state of the device.
_ADB_GET_STATE = "adb get-state"


# Helper function taken from:
# https://docs.python.org/3.8/library/itertools.html#itertools-recipes

def pairwise(iterable):
    """s -> (s0,s1), (s1,s2), (s2, s3), ..."""
    a, b = itertools.tee(iterable)
    next(b, None)
    return zip(a, b)


@dataclasses.dataclass(order=True)
class Frame:
    """Latency information of a frame."""

    # When the app started to draw, in ns.
    draw: int

    # The vsync immediately preceding SF submitting the frame to the h/w, in
    # ns.
    vsync: int

    # Timestamp immediately after SF submitted that frame to the h/w, in ns.
    submit: int


class FPS:
    """Obtains the frame statistics for the targeted package id.

    Obtains the following frame statistics:
        Average FPS.
        [EXPERIMENTAL FEATURE] Latencies (mean, stdev, min, max).

    Attributes:
        package_name: A string matching the full package name.
        duration: An integer count of time spent for the session.
        dumpfile: A string matching the name of file where we want to store
            the information of each frame recorded during the session.
        print_latency: A boolean indicating if we like to print the latencies
            or not.
        require_full_name: A boolean indicating if we like to pass full package
            name or not.
    """

    def __init__(self, package_name: str, duration: int, dumpfile: str,
                 print_latency: bool, require_full_name: bool):
        self._surface_name = None
        self._package_name = package_name
        self._frames = []
        # Contains the last saved timestamp. Used to filter out duplicates.
        self._last_timestamp = -1

        # Screen refresh period in nanoseconds e.g: 1/60Hz * nanosecond.
        self._refresh_period = None
        self._start_time = None

        # Duration in seconds.
        self._duration = duration

        # Stores frame timestamps.
        self._dumpfile = dumpfile

        # Indicates to print the frame latencies or not.
        self._print_latency = print_latency

        # Skip partial name check.
        self._require_full_name = require_full_name

        # Checks whether the device is connected or not.
        # Runs the adb "get-state" command and returns False if an error was
        # returned.
        try:
            subprocess.check_output(_ADB_GET_STATE.split())
        except subprocess.CalledProcessError:
            logging.error("Please check your ADB connection.")
            sys.exit(1)

        package_name = self._validate_package_name(package_name)

        # IGNORECASE is needed because some package names use uppercase
        # letters.
        # Prefer the window name that starts with "SurfaceView" first.
        # Example:
        # SurfaceView - com.example.app/com.test.example.app#0
        pattern_with_surface = rf"""^SurfaceView\s*-\s*
                        (?P<package>{package_name})     # Package name
                        /[\w.#]*$"""                    # Surface window
        self._re_surface = re.compile(
            pattern_with_surface, re.MULTILINE | re.IGNORECASE | re.VERBOSE)

        # Some games like com.playdead.limbo.full don't have one, so we
        # also have a regex without SurfaceView.
        pattern_without_surface = rf"""^(?P<package>{package_name}) # Package name
                            /[\w.#]*$"""                            # Surface window
        self._re_without_surface = re.compile(
            pattern_without_surface, re.MULTILINE | re.IGNORECASE | re.VERBOSE)

        self._surface_name = self._get_surface_name(package_name)
        logging.debug(f'Package name: {package_name}, duration: {duration}s')
        logging.debug(f'Found surface name: "{self._surface_name}"')

    def _validate_package_name(self, package_name: str) -> str:
        """Returns whether package_name is installed.

        Checks whether package_name is installed. package_name could be a
        partial name. Returns the full package name if only one entry matches.
        if more than one matches, it exits with an error.

        To avoid using partial name matches, -f should be used from command
        line.

        Args:
            package_name: A string representing the name of the application to
                be targeted.

        Returns:
            A string representing a validated full package name.
        """
        cmd = ('adb', 'shell', 'pm', 'list', 'packages')
        outstr = subprocess.run(cmd, check=True, encoding='utf-8',
                                capture_output=True).stdout.strip()

        partial_pkg_regexp = fr'^package:(.*{re.escape(package_name)}.*)$'
        full_pkg_regexp = fr'^package:({re.escape(package_name)})$'

        regexp = partial_pkg_regexp
        if self._require_full_name:
            regexp = full_pkg_regexp

        # IGNORECASE is needed because some package names use uppercase letters.
        matches = re.findall(regexp, outstr, re.MULTILINE | re.IGNORECASE)
        if len(matches) == 0:
            print(f'No installed package matches "{package_name}"')
            sys.exit(2)

        if len(matches) > 1:
            print(f'More than one package matches "{package_name}":')
            for p in matches:
                print(f' - {p}')
            sys.exit(3)

        print(f'Found package name: "{matches[0]}"')
        self._package_name = matches[0]
        return matches[0]

    def _get_surface_name(self, package_name: str) -> str:
        """
        Returns the surface name for a given package name.

        Args:
            package_name: A string representing the name of the application to
                be targeted.

        Returns:
            A string representing a surface name of the package name.
        """
        cmd = ('adb', 'shell', 'dumpsys', 'SurfaceFlinger', '--list')
        surfaces_list = subprocess.run(cmd, check=True, encoding='utf-8',
                                       capture_output=True).stdout.strip()
        last = None
        for match in self._re_surface.finditer(surfaces_list):
            last = match
        if last:
            assert package_name == last.group('package'),\
                (f'Surface not found for package {package_name}. '
                 'Please ensure the app is running.')

            # UE4 games have at least two SurfaceView surfaces. The one
            # that seems to in the foreground is the last one.
            return last.group()

        # Fallback: SurfaceView was not found.
        matches_without_surface = self._re_without_surface.search(
            surfaces_list)
        if matches_without_surface:
            assert package_name == matches_without_surface.group('package'),\
                (f'Surface not found for package {package_name}. '
                 'Please ensure the app is running.')
            return matches_without_surface.group()

        assert False, (f'Surface not found for package {package_name}. '
                       'Please ensure the app is running.')

    def _get_recent_frames(self) -> List[Frame]:
        """Returns a list of Frames."""
        assert self._surface_name, ('_get_recent_frames() should not be'
                                    ' called before _get_surface_name().')

        cmd = ('adb', 'shell', 'dumpsys', 'SurfaceFlinger', '--latency',
               f'"{self._surface_name}"')
        output = subprocess.run(cmd, check=True, capture_output=True,
                                encoding='utf-8').stdout.strip()
        lines = output.split('\n')

        # adb shell dumpsys SurfaceFlinger --latency <window name>
        # prints some information about the last 127 frames displayed in
        # that window.
        # The data returned looks like this:
        # 16954612
        # 7657467895508   7657482691352   7657493499756
        # 7657484466553   7657499645964   7657511077881
        # 7657500793457   7657516600576   7657527404785
        # (...)
        #
        # The first line is the refresh period (here 16.95 ms), it is followed
        # by 127 lines w/ 3 timestamps in nanosecond each:
        # A) when the app started to draw.
        # B) the vsync immediately preceding SF submitting the frame to the h/w.
        # C) timestamp immediately after SF submitted that frame to the h/w.
        #
        # We use the special "SurfaceView" window name because the statistics for
        # the activity's main window are not updated when the main web content is
        # composited into a SurfaceView.

        assert len(lines) > 1, ('Frames not found. '
                                'Please ensure the app is running and retry.')

        # The first line is always the refresh period.
        self._refresh_period = int(lines.pop(0))

        frames = []
        for line in lines:
            # Skips empty lines.
            if len(line) == 0:
                continue

            # The three entries are separated by a tab (\t).
            entries = [int(entry) for entry in line.split('\t')]

            # If a fence associated with a frame is still pending when we query the
            # latency data, SurfaceFlinger gives the frame a timestamp of INT64_MAX.
            # Since we only care about completed frames, we will ignore any timestamps
            # with this value.
            # Usually this is not a problem since by the time of the next
            # "_get_recent_frames", the pending one will be completed, and the new
            # value will be used.
            INT64_MAX = (1 << 63) - 1
            if INT64_MAX in entries:
                continue

            # Some entries could be empty. e.g: when the SF stats are cleared and
            # immediately this function is called.
            if entries[0] == 0:
                continue

            frames.append(
                Frame(draw=entries[0], vsync=entries[1], submit=entries[2]))
        return frames

    def print_stats(self, frames: List[Frame]) -> None:
        """
        Prints the stats of the list of Frames.

        Args:
            frames: List of latest 127 frames.
        """

        # It might be possible that 'frames' is almost empty (e.g. SF stats were
        # recently cleared). When that's the case, don't print anything.
        # Three is the minimum required to generate two values needed for stdev.
        if len(frames) < 3:
            return
        total = len(frames) - 1
        dt = (frames[-1].vsync - frames[0].vsync) / 1000000000
        avg = total / dt

        # Line overwrites itself with '\r'.
        fps_avg = f'\r- FPS avg={avg:.2f} '
        latency_str = ''
        if self._print_latency:
            # Store latencies in milliseconds.
            latencies = [(f.submit-f.draw) / 1000000 for f in frames]
            latency_str = ('/ LATENCY (ms) '
                           f'mean={statistics.mean(latencies):.2f}, '
                           f'stdev={statistics.stdev(latencies):.2f}, '
                           f'min={min(latencies):.2f}, '
                           f'max={max(latencies):.2f}')

        print(f'{fps_avg}{latency_str}', end='')

    def print_summary(self) -> None:
        """Prints a summary of the session."""

        # Add extra line, otherwise it will get overwritten.
        print('\n\n...Stats of the entire session...')
        print(f'- Package name: {self._package_name}')
        print(f'- Refresh rate: {1000000000 / self._refresh_period:.2f}Hz')
        print(f'- Total frames: {len(self._frames)}, '
              f'elapsed time: {time.time() - self._start_time:.2f}s')
        self.print_stats(self._frames)
        print()
        self.dump_frames()

    def dump_frames(self) -> None:
        """Dumps all collected frames into a file.

        Useful mostly for debugging purposes.
        """
        if self._dumpfile is None:
            return
        with open(self._dumpfile, 'w') as fd:
            fd.write((f'{self._refresh_period} - '
                      f'{1000000000 / self._refresh_period:.2f}Hz\n'))
            for prev_f, curr_f in pairwise(self._frames):
                diff = curr_f.vsync - prev_f.vsync
                fps = 1000000000 / diff
                fd.write((f'{curr_f.draw}\t{curr_f.vsync}\t{curr_f.submit} - '
                          f'vsync dt={diff/1000000:.2f}ms ({fps:.2f}fps), '
                          f'latency={(curr_f.submit - curr_f.draw)/1000000:.2f}ms\n'))
            fd.close()
            print(f'\nDump saved in file {self._dumpfile}')

    def run(self) -> None:
        """Collects the frame latency statistics.

        This function will run until Ctrl+C is pressed or until
        timeout.
        """
        self.clear_stats()
        self._start_time = time.time()
        print(f'\nStats of latest 127 frames for: {self._package_name}')
        while time.time() - self._start_time < self._duration:
            frames = self._get_recent_frames()
            # Saves only the "newer" frames.
            for f in frames:
                if f.draw > self._last_timestamp:
                    self._frames.append(f)

            # When "_get_recent_frames" is called immediately after clearing the stats,
            # it might be possible that "_get_recent_frames" returns an emtpy list.
            if len(frames) > 0:
                self._last_timestamp = frames[-1].draw

            self.print_stats(frames)

            # "_get_recent_frames" captures the most 127 recent frames.
            # If it runs at 60Hz we have a window of ~2 seconds without losing any
            # frame: (1/60) * 127 == ~2.1 seconds.
            # Some devices, like Pixel 4, run at 90Hz, so ~1.4 seconds is required.
            # But to be ultra safe, we use 0.5s sleep which is good for screens
            # up to ~250Hz.
            # TODO(ricardoq): Get screen refresh period in runtime.
            time.sleep(0.5)
        self.print_summary()

    def clear_stats(self) -> None:
        """Clears the previous session stats."""
        assert self._surface_name, ('clear_stats() should not be called before '
                                    '_get_surface_name()')

        cmd = ('adb', 'shell', 'dumpsys', 'SurfaceFlinger', '--latency-clear',
               f'"{self._surface_name}"')
        subprocess.run(cmd, check=True)


def start():
    parser = argparse.ArgumentParser(description='FPS/latency monitor.' +
                                     'ADB connection required.')
    ONE_DAY_IN_SECONDS = datetime.timedelta(days=1).total_seconds()
    parser.add_argument('-d', '--duration',
                        help='duration in seconds',
                        default=ONE_DAY_IN_SECONDS, type=int)
    parser.add_argument('-o', '--dump', metavar='FILENAME',
                        help='filename where frames will be dumped')
    parser.add_argument('package_name', help=('package name to evaluate.'))
    parser.add_argument('-l', '--print_latency', action='store_true',
                        help='displays the frame latency')
    parser.add_argument('-f', '--full', action='store_true',
                        help='Requires full package name. Partial name is not'
                        ' supported.')
    args = parser.parse_args()
    latency = FPS(
        args.package_name, args.duration, args.dump, args.print_latency, args.full)

    # Handles termination of the process.
    def signal_handler(signum, frame):
        # To make linter happy about unused args.
        _, _ = signum, frame
        print('\nCtrl-C pressed')
        latency.print_summary()
        sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)

    # Collects the frame latency stats.
    latency.run()


if __name__ == '__main__':
    start()
