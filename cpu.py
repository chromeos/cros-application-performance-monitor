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

"""Retrieves CPU related information for the target package id.

Provides current app and device usage.
Calculates peak CPU usage, average application usage, average device usage and
maximum application usage.

To run this script with the CLI:
Syntax:
python3 cpu.py [-d <time-in-seconds>] [-o <output-file>] package_id

Arguments:
    package_id: (Required) Package name of the application.
    duration or d: (optional) Duration of time we run this script. By default
                the duration is 1 day.
    dump or o: (Optional) File name where stats are stored. By default, the data is
        stored in cpu_dump.txt.
Example:
    python3 cpy.py -d 30 -o example.txt com.example.app
"""

import argparse
import datetime
import logging
import re
import signal
import statistics
import subprocess
import sys
import time

# Top command to display the list of running processes.
_ADB_SHELL_TOP = "adb shell top -bn1"

# ADB command to get the state of the device.
_ADB_GET_STATE = "adb get-state"


class CPU:
    """Obtains the CPU information for the targeted package id.

    Collects the following information:
        Peak application usage as a percent.
            Peak usage is calculated by taking the CPU used by the application
            divided by the total CPU used by the device, as a percentage:
                (CPU_USED_BY_APP/OVERALL_CPU_USED * 100)
        The frequency of each CPU core.
        The application's CPU usage as a percent.
        The device's CPU usage as a percent.
    """

    def __init__(self, package_id):
        # The percentage of the CPU used by the app.
        self._app_usage = None

        # The percentage of the CPU used by the device.
        self._device_usage = None

        # The max percetage of CPU used by the app.
        self._max_cpu_usage = None

        # The package name of the application.
        self._package_name = package_id

        # The maximum percentage of the CPU which is available for the device.
        self._max_cpu = 0

        # A list of CPU usage by the app as a percent of total CPU(includes
        # all the cores) usage.
        self._app_values = []

        # A list of CPU usage by the device as a percent of total CPU(includes
        # all the cores) usage.
        self._device_values = []

        # The percentage of the CPU used by the app relative to the device.
        self._peak_cpu_usage = None

        # The average percentage of CPU used by the app.
        self._mean_app_usage = None

        # The average percentage of CPU used by the device.
        self._mean_device_usage = None

        # TODO(danduri@): Validate whether the "top" command is valid for
        # different android versions.
        # "adb shell top -bn1" output:
        #
        # Tasks: 87 total, 1 running, 86 sleeping, 0 stopped, 0 zombie
        # Mem: 16303480k total, 6469956k used, 9833524k free, 437844k buffers
        # Swap: 23882048k total, 0k used, 23882048k free, 3994852k cached
        # 400%cpu 48%user 0%nice 30%sys 322%idle 0%iow 0%irq 0%sirq 0%host
        #   PID USER        PR  NI VIRT  RES  SHR S[%CPU] %MEM     TIME+ ARGS
        #  6376 u0_a66      15  -5 1.8G 585M 234M S 40.7   3.6 5:37.52 process1
        #    11 system      -2  -4  61M  30M  17M S  7.4   0.1 8:56.55 process2
        # 26265 shell       20   0  11M 3.2M 2.7M R  3.7   0.0 0:00.03 process3
        # ...
        pattern_app = rf"""^\s*(?P<pid>\d+)\s*   # PID
                (?P<user>\S+)\s*                # User name
                (?P<pri>-?\d+)\s*               # Priority
                (?P<nice>-?\d+)\s*              # Nice
                (?P<virt>\S+)\s*                # Virtual Image(kb)
                (?P<res>\S+)\s*                 # Resident size(kb)
                (?P<shr>\S+)\s*                 # Shared Mem size (kb)
                (?P<S>\S+)\s*                   # Process status
                (?P<cpu>[0-9.]+)\s*             # CPU usage
                (?P<mem>[0-9.]+)\s*             # Memory usage (RES)
                (?P<time>[0-9:.]+)\s*           # CPU Time
                (?P<args>{self._package_name})$ # Package/Process name
                """
        self._re_app = re.compile(pattern_app, re.MULTILINE | re.VERBOSE)

        pattern_cpu = r"""^\s*(?P<cpu>\d+)%cpu\s*      # %CPU
                (?P<user>\d+)\s*%user\s*               # %User
                (?P<nice>\d+)%nice\s*                  # %Nice
                (?P<sys>\d+)%sys\s*                    # %System
                (?P<idle>\d+)%idle\s*                  # %Idle
                (?P<iow>\d+)%iow\s*                    # %IO waiting time
                (?P<irq>\d+)%irq\s*                    # %Hard interrupt time
                (?P<sirq>\d+)%sirq\s*                  # %Soft interrupt time
                (?P<host>\d+)%host                     # %Host
                """
        self._re_cpu = re.compile(pattern_cpu, re.MULTILINE | re.VERBOSE)

        # Checks whether the device is connected or not.
        # Runs the adb "get-state" command and returns False if an error was
        # returned.
        try:
            subprocess.check_output(_ADB_GET_STATE.split())
        except subprocess.CalledProcessError:
            logging.error("Please check your ADB connection.")
            sys.exit(1)

    def _gather_cpu_usage(self) -> None:
        """Stores the percentage of CPU used by the application and the
        device.

        Stores CPU usage in the following properties:
            _app_usage
            _device_usage
                Calculated as:
                    (MAX_CPU_AVAILABLE(400%)-IDLE_CPU_USAGE(322%)
            _app_values
            _device_values
        """

        top_output = subprocess.check_output(
            _ADB_SHELL_TOP.split()).strip().decode()

        app_matches = self._re_app.search(top_output)
        if not app_matches:
            logging.error(f"\nRegex: Match for {self._package_name}"
                          " not found in top output")
            sys.exit(1)

        app_cpu = app_matches.group("cpu")
        assert app_cpu, "Application CPU usage values are not recorded."
        self._app_usage = float(app_cpu)

        # Captures regex group(line) containing the CPU idle usage info.
        cpu_matches = self._re_cpu.search(top_output)
        if not cpu_matches:
            logging.error("\nRegex: Match for (percentage)idle cpu usage not "
                          "found in top output")
            sys.exit(1)

        idle_cpu = float(cpu_matches.group("idle"))
        self._max_cpu = float(cpu_matches.group("cpu"))

        assert idle_cpu, "CPU idle values are not recorded."
        assert self._max_cpu, "CPU max value is not recorded."
        self._device_usage = self._max_cpu - idle_cpu

        # Stores app and device usage for later calculations.
        self._app_values.append(self._app_usage)
        self._device_values.append(self._device_usage)

    def _update_cpu_calculations(self) -> None:
        """Updates the mean of the application and device CPU usage recorded
        in the session.
        """

        assert self._app_values, "Failed to get values for app CPU usage."
        assert self._device_values, ("Failed to get values for device"
                                     " CPU usage.")
        assert len(self._app_values) == len(self._device_values), \
            ("Invalid data, expected matching app usage and device usage"
             " values")

        # Calculates average app CPU usage as a percent of total CPU.
        self._mean_app_usage = (statistics.mean(
            self._app_values) / self._max_cpu) * 100

        # Calculates average device CPU usage as a percent of total CPU.
        self._mean_device_usage = (statistics.mean(
            self._device_values) / self._max_cpu) * 100

        peak_usage_array = []
        # Calculates average app CPU usage as a percent of total CPU.
        for app, total in zip(self._app_values, self._device_values):
            assert total, ("Expected device usage value to be a float greater"
                           " than 0")
            peak_usage_array.append(app / total)

        self._peak_cpu_usage = statistics.mean(peak_usage_array) * 100
        self._max_cpu_usage = max(self._app_values) / self._max_cpu * 100

    def print_summary(self) -> None:
        """Prints a summary of the CPU information."""
        self._update_cpu_calculations()

        values = [
            self._mean_app_usage,
            self._mean_device_usage,
            self._peak_cpu_usage,
            self._max_cpu_usage,
        ]

        # Ensures values were calculated.
        # The data needed for these results has been validated. Therefore, the results
        # will be valid and this assert will likely not be reached.
        assert all(values), (f"Empty data found, expected non-null values. "
                             "{values}")

        values = [round(num, 2) for num in values]

        print("\n"
              "===================================\n"
              "          CPU summary \n"
              "===================================\n"
              f"Average application usage = {values[0]}%\n"
              f"Average device usage = {values[1]}%\n"
              f"Relative/Peak application usage = {values[2]}%\n"
              f"Maximum application usage: {values[3]}%\n")

    def run(self, args: argparse.Namespace) -> None:
        """Collects the CPU information.

        This function will run forever until Ctrl+C is pressed or until
        timeout.

        Arguments:
            args -> Arguments used for the CLI version.
        """
        start_time = time.time()

        while time.time() - start_time < args.duration:
            self._gather_cpu_usage()

            print(f"\r-CPU({self._max_cpu}%): "
                  f"Application={self._app_usage:.2f}%, "
                  f"Device={self._device_usage:.2f}%", end="")

            time.sleep(0.5)

        print()
        self.print_summary()


def _start() -> None:
    """Starts collecting CPU information.

    Parses args from CLI and starts collecting CPU information.
    """
    parser = argparse.ArgumentParser(description="CPU monitor." +
                                     "ADB connection required.")
    one_day_in_seconds = datetime.timedelta(days=1).total_seconds()
    parser.add_argument("-d", "--duration",
                        help="duration in seconds",
                        default=one_day_in_seconds, type=int)
    parser.add_argument("package_id", help=("package name to evaluate. "
                                            "Must be complete package name, ex: "
                                            "com.example.exmapleAppII"))

    args = parser.parse_args()
    cpu_module = CPU(args.package_id)

    # Handles termination of the process.
    def signal_handler(_signum, _frame):
        print("\nCtrl-C pressed")
        cpu_module.print_summary()
        sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)

    # Collects the CPU information for the given arguments.
    cpu_module.run(args)


if __name__ == "__main__":
    _start()
