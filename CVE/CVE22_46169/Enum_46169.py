from Metode import *

class CEnum(Enumerator):

    def __init__(self):
        super().__init__()

    def enumTarget(self):
        results = self.parse_nmap_results(self.sourceFile)
        self.save_results_to_txt(results)

    def parse_nmap_results(self, filename):
        open_ports = {}
        if filename is None:
            raise ValueError("Filename cannot be none. Please provide a valid file path")
        
        with open(filename, "r") as file:
            lines = file.readlines()
            ip = None
            current_port_info = None
            for line in lines:
                if "Nmap scan report for" in line:
                    ip = line.split()[-1].strip()
                    open_ports[ip] = []
                elif "/tcp" in line and ip:
                    parts = line.split()
                    port = parts[0].split("/")[0]
                    protocol = parts[0].split("/")[1]
                    state = parts[1]
                    service_info = {}
                    service_info["service"] = parts[2]
                    if len(parts) > 3:
                        service_info["version"] = " ".join(parts[3:])
                    current_port_info = {"port": port, "protocol": protocol, "state": state, "service": service_info.get("service"), "info": service_info}
                    #print(f"info {current_port_info}")
                elif line.startswith("|_  /cacti/:") and current_port_info:
                    print("aku di sini")
                    http_title = " ".join(line.split(":")[1:]).strip()
                    current_port_info["info"]["http-title"] = http_title
                    print(http_title.lower())
                    if "cacti web monitoring" in http_title.lower():
                        print(f"Web Server: {http_title}")
                        open_ports[ip].append(current_port_info)
                    current_port_info = None  # Reset after processing
                """ elif line.startswith("|_http-title:") and current_port_info:
                    print("aku di sini")
                    http_title = " ".join(line.split(":")[1:]).strip()
                    current_port_info["info"]["http-title"] = http_title
                    print(http_title.lower())
                    if "403" in http_title.lower():
                        print("403 Forbidden")
                        open_ports[ip].append(current_port_info)
                    current_port_info = None  # Reset after processing """
        return open_ports
    
    def save_results_to_txt(self, results):
        print(f"Results: {results}")
        with open(self._outEnumFile, "w") as file:
            for ip, ports in results.items():
                print(f"IP {ip} \n ports {ports}")
                for port in ports:
                    if port["state"] == "open":
                        file.write(f"{ip}  {port['port']}\n")

    def setTarget(self, IPAddrs):
        return super().setTarget(IPAddrs)
    
    def setTool(self, tool, params):
        return super().setTool(tool, params)
