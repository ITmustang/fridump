import textwrap
import frida
import os
import sys
import frida.core
import dumper
import utils
import argparse
import logging

logo = r"""
        ______    _     _
        |  ___|  (_)   | |
        | |_ _ __ _  __| |_   _ _ __ ___  _ __
        |  _| '__| |/ _` | | | | '_ ` _ \| '_ \\
        | | | |  | | (_| | |_| | | | | | | |_) |
        \_| |_|  |_|\__,_|\__,_|_| |_| |_| .__/
                                         | |
                                         |_|
        """


# Main Menu
def MENU():
    parser = argparse.ArgumentParser(
        prog='fridump',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(""))

    parser.add_argument('process', nargs='?',
                        help='the process/app to inject into (omit when using -l/--list)')
    parser.add_argument('-l', '--list', action='store_true',
                        help='list applications on the device and exit')
    parser.add_argument('-o', '--out', type=str, metavar="dir",
                        help='provide full output directory path. (def: \'dump\')')
    parser.add_argument('-U', '--usb', action='store_true',
                        help='device connected over usb')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='verbose')
    parser.add_argument('-r', '--read-only', action='store_true',
                        help="dump read-only parts of memory. More data, more errors")
    parser.add_argument('-s', '--strings', action='store_true',
                        help='run strings on all dump files. Saved in output dir.')
    parser.add_argument('--max-size', type=int, metavar="bytes",
                        help='maximum size of dump file in bytes (def: 20971520)')
    args = parser.parse_args()
    return args


def list_applications(usb):
    try:
        device = frida.get_usb_device() if usb else frida.get_local_device()
    except Exception as e:
        print("Can't connect to the device. Is it connected and unlocked?")
        logging.debug(str(e))
        sys.exit(1)
    try:
        apps = device.enumerate_applications()
    except Exception as e:
        print("Could not enumerate applications: " + str(e))
        sys.exit(1)
    # running apps (pid != 0) first, then alphabetical by name
    apps = sorted(apps, key=lambda a: (a.pid == 0, (a.name or "").lower()))
    print("\n{:<8} {:<34} {}".format("PID", "Name", "Identifier"))
    print("-" * 78)
    for app in apps:
        pid = str(app.pid) if app.pid else "-"
        name = (app.name or "")[:34]
        print("{:<8} {:<34} {}".format(pid, name, app.identifier))
    print("")


print(logo)

arguments = MENU()

# Handle --list: enumerate apps and exit before attaching to anything
if arguments.list:
    list_applications(arguments.usb)
    sys.exit(0)

# A process is required for an actual dump
if arguments.process is None:
    print("error: a process/app name is required for dumping (or use -l to list apps)")
    sys.exit(1)

# Define Configurations
APP_NAME = arguments.process
DIRECTORY = ""
USB = arguments.usb
DEBUG_LEVEL = logging.INFO
STRINGS = arguments.strings
MAX_SIZE = 20971520
PERMS = 'rw-'

if arguments.read_only:
    PERMS = 'r--'

if arguments.verbose:
    DEBUG_LEVEL = logging.DEBUG
logging.basicConfig(format='%(levelname)s:%(message)s', level=DEBUG_LEVEL)


# Start a new Session
session = None
try:
    if USB:
        session = frida.get_usb_device().attach(APP_NAME)
    else:
        session = frida.attach(APP_NAME)
except Exception as e:
    print("Can't connect to App. Have you connected the device?")
    logging.debug(str(e))
    sys.exit()


# Selecting Output directory
if arguments.out is not None:
    DIRECTORY = arguments.out
    if os.path.isdir(DIRECTORY):
        print("Output directory is set to: " + DIRECTORY)
    else:
        print("The selected output directory does not exist!")
        sys.exit(1)

else:
    print("Current Directory: " + str(os.getcwd()))
    DIRECTORY = os.path.join(os.getcwd(), "dump")
    print("Output directory is set to: " + DIRECTORY)
    if not os.path.exists(DIRECTORY):
        print("Creating directory...")
        os.makedirs(DIRECTORY)

mem_access_viol = ""

print("Starting Memory dump...")

script = session.create_script(
    r"""'use strict';

    rpc.exports = {
      enumerateRanges: function (prot) {
        return Process.enumerateRanges({protection: prot, coalesce: true});
      },
      readMemory: function (address, size) {
        return new NativePointer(address).readByteArray(size);
      }
    };

    r""")
script.on("message", utils.on_message)
script.load()

agent = script.exports_sync
ranges = agent.enumerate_ranges(PERMS)

if arguments.max_size is not None:
    MAX_SIZE = arguments.max_size

i = 0
l = len(ranges)

# Performing the memory dump
for range in ranges:
    base = range["base"]
    size = range["size"]

    logging.debug("Base Address: " + str(base))
    logging.debug("")
    logging.debug("Size: " + str(size))


    if size > MAX_SIZE:
        logging.debug("Too big, splitting the dump into chunks")
        mem_access_viol = dumper.splitter(
            agent, base, size, MAX_SIZE, mem_access_viol, DIRECTORY)
        continue
    mem_access_viol = dumper.dump_to_file(
        agent, base, size, mem_access_viol, DIRECTORY)
    i += 1
    utils.printProgress(i, l, prefix='Progress:', suffix='Complete', bar=50)
print("")

# Run Strings if selected

if STRINGS:
    files = os.listdir(DIRECTORY)
    i = 0
    l = len(files)
    print("Running strings on all files:")
    for f1 in files:
        utils.strings(f1, DIRECTORY)
        i += 1
        utils.printProgress(i, l, prefix='Progress:', suffix='Complete', bar=50)
print("Finished!")
