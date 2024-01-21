import paramiko
import time
from datetime import datetime


def ssh_connect(host, username, private_key_path, alias):
    client = paramiko.SSHClient()

    try:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        private_key = paramiko.RSAKey(filename=private_key_path)

        client.connect(host, username=username, pkey=private_key)

        stdin, stdout, stderr = client.exec_command("systemctl status mysql")
        status_output = stdout.read().decode()

        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"Connecting to {alias} - {host} at {current_time}")

        if "active (running)" in status_output:
            print(f"MySQL on {alias} - {host} is active (alive).")
        else:
            print(f"MySQL on {alias} - {host} is inactive (dead).")
            print("Waiting for a minute... I'm trying to wake it up!")
            time.sleep(5)

            stdin, stdout, stderr = client.exec_command(
                "systemctl start mysql ; systemctl status mysql")
            status_output_after_start = stdout.read().decode()

            if "active (running)" in status_output_after_start:
                print(
                    f"Done! MySQL on {alias} - {host} is now active (alive).")
            else:
                print(f"Something went wrong with {alias} - {host}.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()


hosts = ["172.16.200.128", "172.16.200.129", "172.16.200.130"]
for i in range(len(hosts)):
    private_key_path = f"/home/hjn4/quantri_sshkey/ubuntu{i + 1}_key"
    alias = f"ubuntu{i+1}"
    ssh_connect(hosts[i], "root", private_key_path, alias)
    print(" - "*20)
print("\n" + "-"*80 + "\n")
