#!/usr/bin/python3

# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Retrieves memory related information for the target package id.

Provides current app and device usage.
Calculates peak memory usage, average application usage, average device usage
and maximum application usage.

To run this script with the CLI:
Syntax:
python3 memory.py [-d <time-in-seconds>] [-o <output-file>] [-f] package_name

Arguments:
    package_name: (Required) Package name of the application.
    duration or d: (optional) Duration of time we run this script. By default
                the duration is 1 day.
    dump or o: (Optional) File name where stats are stored. By default, the data is
        stored in memory_dump.txt.
    full or f: (Optional) A boolean indicating if we like to skip the partial
        name or not. We have to input full package when this argument is passed.

Example:
    python3 memory.py -d 30 -o example.txt com.example.app
"""

import argparse
import logging
import datetime
import re
import signal
import statistics
import subprocess
import sys
import time

# ADB command to display the list of running processes.
_ADB_SHELL_TOP = "adb shell top -bn1"

_KIB_TO_MIB = 1/1024


class Memory:
    """Obtains the memory information for the targeted package id.

    Collects the following information:
        Peak application usage as a percent.
            Peak usage is calculated by taking the memory used by the application
            divided by the total memory used by the device, as a percentage:
                (MEM_USED_BY_APP/OVERALL_MEM_USED * 100)
        The application's memory usage as a percent.
        The device's memory usage as a percent.
    """

    def __init__(self,  package_name: str, require_full_name: bool):
        # The package name of the application.
        self._package_name = package_name

        # The max amount of total memory used by the app.
        self._max_app_usage = None

        # The total device memory (Mb).
        self._total_mem = None

        # A list of memory usage by the app.
        self._app_values = []

        # A list of memory usage by the device.
        self._device_values = []

        # The average percentage of memory used by the app relative to the
        # device.
        self._peak_mem_usage = None

        # The average amount of memory used by the app.
        self._mean_app_usage = None

        # The average amount of memory used by the device.
        self._mean_device_usage = None

        # Top output returns a string as follows:
        # Tasks: 87 total, 1 running, 86 sleeping, 0 stopped, 0 zombie
        #
        # Mem: 16303480k total, 6469956k used, 9833524k free, 437844k buffers
        # Swap: 23882048k total, 0k used, 23882048k free, 3994852k cached
        # 400%cpu 48%user 0%nice 30%sys 322%idle 0%iow 0%irq 0%sirq 0%host
        #   PID USER        PR  NI VIRT  RES  SHR S[%CPU] %MEM     TIME+ ARGS
        #  6376 u0_a66      15  -5 1.8G 585M 234M S 40.7   3.6 5:37.52 process1
        #    11 system      -2  -4  61M  30M  17M S  7.4   0.1 8:56.55 process2
        # 26265 shell       20   0  11M 3.2M 2.7M R  3.7   0.0 0:00.03 process3
        #    40 audioserver 20   0 128M  20M  17M S  3.7   0.1 4:52.32 process4
        # 25127 bluetooth   20   0 3.0G 107M  93M S  0.0   0.6 0:00.17 process5
        # ............
        pattern_top_mem = rf"""^\s*Mem:
                \s*(?P<total>\d+)\w*\s*total,    # Total
                \s*(?P<used>\d+)\w*\s*used,      # used
                \s*(?P<free>\d+)\w*\s*free,      # Free memory
                \s*(?P<buffer>\d+)\w*\s*buffers  # Buffer memory
                """
        self._re_top_mem = re.compile(
            pattern_top_mem, re.MULTILINE | re.VERBOSE)

        # Output from adb shell dumpsys meminfo command to obtain app usage.
        # ** MEMINFO in pid 22328 [com.example.app] **
        #  ......
        #  App Summary
        #                        Pss(KB)
        #                         ------
        #            Java Heap:     2716
        #          Native Heap:   376872
        #                 Code:    61232
        #                Stack:       44
        #             Graphics:        0
        #        Private Other:   129320
        #               System:     6115
        #
        #                TOTAL:   576299       TOTAL SWAP PSS:        0
        #  ......
        #   Android R, the output of interest is slightly different:
        #               TOTAL PSS:   123    TOTAL RSS:  456   TOTAL SWAP(KB): 0
        #  ......

        pattern_dumpsys_mem_p = r"""^
                \s*TOTAL:\s*(?P<total>\d+)
                \s*TOTAL\s*SWAP\s*PSS:\s*(?P<swap>\d+)$
                """
        pattern_dumpsys_mem_r = r"""^
                \s*TOTAL\s*PSS:\s*(?P<total>\d+)
                \s*TOTAL\s*RSS:\s*(?P<totalRSS>\d+)
                \s*TOTAL\s*SWAP\s*\(KB\):\s*(?P<swap>\d+)\s*$
                """

        # Checks whether the device is connected or not.
        try:
            subprocess.check_output(["adb", "get-state"])
        except subprocess.CalledProcessError:
            logging.error("Please check your ADB connection.")
            sys.exit(1)

        # ADB command to obtain the android version of the device
        cmd = ("adb", "shell", "getprop", "ro.build.version.release")
        self._re_dumpsys = None
        android_ver = subprocess.check_output(cmd).strip().decode()
        if android_ver == "11":
            # Compile for verison R
            self._re_dumpsys = re.compile(
                pattern_dumpsys_mem_r, re.MULTILINE | re.VERBOSE)
        elif android_ver == "9":
            # Compile for version P
            self._re_dumpsys = re.compile(
                pattern_dumpsys_mem_p, re.MULTILINE | re.VERBOSE)
        else:
            print(f"Unsupported Android version: {android_ver}. "
                  "Only works on versions 9 and 11")
            sys.exit(1)

        self._require_full_name = require_full_name
        self._package_name = self._validate_package_name(package_name)

        # Initializes the total memory.
        self._gather_total_mem()

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
        cmd = ("adb", "shell", "pm", "list", "packages")
        outstr = subprocess.run(cmd, check=True, encoding="utf-8",
                                capture_output=True).stdout

        partial_pkg_regexp = fr"^package:(.*{re.escape(package_name)}.*)$"
        full_pkg_regexp = fr"^package:({re.escape(package_name)})$"

        regexp = partial_pkg_regexp
        if self._require_full_name:
            regexp = full_pkg_regexp

        # IGNORECASE is needed because some package names use uppercase letters.
        matches = re.findall(regexp, outstr, re.MULTILINE | re.IGNORECASE)
        if len(matches) == 0:
            print(f"No installed package matches '{package_name}'")
            sys.exit(2)

        if len(matches) > 1:
            print(f"More than one package matches '{package_name}':")
            for p in matches:
                print(f" - {p}")
            sys.exit(3)

        print(f"Found package name: '{matches[0]}'")
        self._package_name = matches[0]
        return matches[0]

    def _gather_total_mem(self) -> None:
        """Obtains the total memory of the device."""
        top_output = subprocess.check_output(_ADB_SHELL_TOP
                                             .split()).strip().decode()

        memory_matches = self._re_top_mem.search(top_output)
        if not memory_matches:
            logging.error((f"Regex: unable to find the pattern matching"
                           f" '{self._re_top_mem}'"))
            sys.exit(1)

        device_total_mem = int(memory_matches.group("total")) * _KIB_TO_MIB
        assert device_total_mem,  "Unable to obtain total memory from deivce."
        self._total_mem = device_total_mem

    def _gather_mem_usage(self) -> None:
        """Collects application and device memory usage.

        Collects application usage from the dumpsys adb shell command and
        collects device usage from the top adb shell command.

        If no matches are found for the application or device usage,
        an error message will be logged and the program will exit.
        """
        # ADB command to obtain the memory information for the targeted package id.
        cmd = ("adb", "shell", "dumpsys", "meminfo", self._package_name)
        dumpsys_output = subprocess.check_output(cmd).decode()

        # Finds app usage from dumpsys, checks P first and fallsback to R.
        app_usage_match = self._re_dumpsys.search(dumpsys_output)
        if not app_usage_match:
            app_usage_match = self._re_dumpsys.search(dumpsys_output)
            if not app_usage_match:
                logging.error((f"Regex did not match this output:\n"
                               f"{dumpsys_output}\n"
                               "_get_mem_usage: failed to parse dumpsys meminfo "
                               f"{self._package_name}"))
                sys.exit(1)

        app_usage = app_usage_match.group("total")
        assert app_usage, "App memory value is not recorded."
        # Finds device usage from top.
        top_output = subprocess.check_output(_ADB_SHELL_TOP
                                             .split()).strip().decode()
        device_match = self._re_top_mem.search(top_output)
        if not device_match:
            logging.error((f"Regex (device): unable to find the pattern"
                           f" matching '{self._re_top_mem}'"))
            sys.exit(1)
        device_usage = device_match.group("used")
        assert device_usage, "Device memory value is not recorded."

        app_usage = float(app_usage) * _KIB_TO_MIB
        device_usage = float(device_usage) * _KIB_TO_MIB
        self._app_values.append(app_usage)
        self._device_values.append(device_usage)

    def _update_mem_calculations(self) -> None:
        """Updates the memory calculations.

        Updates the mean application and device memory usage, peak and max
        memory usage recorded in the session.
        """
        # The mean application memory usage.
        self._mean_app_usage = statistics.mean(self._app_values)

        # Calculates the mean memory usage by the device.
        self._mean_device_usage = statistics.mean(self._device_values)

        # Calculates the peak memory usage by the app.
        peak_usage = []
        for app, total in zip(self._app_values, self._device_values):
            assert total, ("Expected device usage value to be a float greater"
                           " than 0.")
            peak_usage.append(app / total)

        assert peak_usage, "Peak usage: Expected non-null values."
        self._peak_mem_usage = statistics.mean(peak_usage) * 100

        # Calculates max memory usage by the app.
        self._max_app_usage = max(self._app_values)

    def run(self, duration: int) -> None:
        """Collects the memory information.

        This function will run until Ctrl+C is pressed or until
        timeout.

        Args:
            duration: Amount of time (in seconds) the script will run. The
                    default is 1 day.
        """
        start_time = time.time()
        while time.time() - start_time < duration:
            self._gather_mem_usage()
            print(("\r-Memory: "
                   f"Application={self._app_values[-1]:.2f}MB, "
                   f"Device={self._device_values[-1]:.2f}MB"),
                  end="")
            time.sleep(0.5)
        self.print_summary()

    def print_summary(self) -> None:
        """Prints a summary of the memory information.

        It is possible that this function might be called before data is
        collected. If self._app_values is empty, it is safe to assume no
        data was collected due to early termination of the program via
        parameter duration=0 or user pressed ctrl-C.
        """

        if(not self._app_values):
            print("No summary available, no values were collected.")
            return

        self._update_mem_calculations()

        print("\n"
              "==============================================\n"
              "               Memory summary \n"
              "==============================================\n"
              f"Total device memory = {self._total_mem:.2f}MB\n"
              f"Peak application usage = {self._peak_mem_usage:.2f}%\n"
              f"Average application usage = {self._mean_app_usage:.2f}MB"
              f" ({(self._mean_app_usage / self._total_mem) * 100:.2f}%)\n"
              f"Average device usage = {self._mean_device_usage:.2f}MB"
              f" ({(self._mean_device_usage / self._total_mem) * 100:.2f}%)\n"
              f"Maximum application usage: {self._max_app_usage:.2f}MB"
              f" ({(self._max_app_usage / self._total_mem) * 100:.2f}%)\n"
              "==============================================\n")


def _start() -> None:
    """Starts running memory collection using the args from the CLI."""
    parser = argparse.ArgumentParser(description="Memory monitor." +
                                     "ADB connection required.")
    one_day_in_seconds = datetime.timedelta(days=1).total_seconds()
    parser.add_argument("-d", "--duration",
                        help="duration in seconds",
                        default=one_day_in_seconds, type=int)
    parser.add_argument("--dump", metavar="FILENAME",
                        help="filename where memory will be dumped",
                        default="memory_dump.txt")
    parser.add_argument("package_name", help=("package name to evaluate. "
                                              "Partial names are "
                                              "accepted as well"
                                              ))
    parser.add_argument("-f", "--full", action="store_true",
                        help="Skips the partial name check when multiple"
                        " packages match. Please enter the full package name.")
    args = parser.parse_args()
    memory = Memory(args.package_name, args.full)

    # Ctrl-C cancels capture, but should print report.
    def signal_handler(_signum, _frame):
        print("\nCtrl-C pressed")
        memory.print_summary()
        sys.exit(1)
    signal.signal(signal.SIGINT, signal_handler)

    # Calculates the memory usage with the given arguments.
    memory.run(args.duration)


if __name__ == "__main__":
    _start()
