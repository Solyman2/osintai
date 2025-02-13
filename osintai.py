import argparse
import json
import requests
import socket
import subprocess
import os
import re
from pathlib import Path

Shodan_API_KEY = "SHODAN_API_KEY"
IPinfo_token = "IPinfo_TOKEN"
BE_API_KEY = "BinaryEdge_API_KEY"
HF_Token = "HugginFace_TOKEN" 

parser = argparse.ArgumentParser(description='OSINTAI')
parser.add_argument('-t', '--target', type=str, required=True, help='target domain or ip')
parser.add_argument('-re', '--reconng', action='store_true', required=False, help='Run Recon-ng recon modules (takes long time)')

args = parser.parse_args()

def main(target):

    IP_addr = resolve_hostname(target)

    print(f"Starting assessment for: {target} - {IP_addr}")
    
    # OSINT
    print("Working on OSINT...")
    whatweb_results = run_whatweb(target)
    Shodan_data = gather_Shodan(IP_addr)
    IPinfo_data = gather_IPinfo(IP_addr)
    AV_data = gather_AV(IP_addr)
    BE_data = gather_BE(IP_addr)
    print("OSINT Data: Done.")

    rec_output = "None"
    if args.reconng is True:
        print("Working on recon-ng...")
        run_recon_ng(target)
        rec_output = f"{target}_recon-g_report.html"
        print("recon-ng Data: Done.")
        print(f"recon-ng Html report written to: {target}_recon-g_report.html")
    


    # Reporting
    generate_report(target ,whatweb_results ,Shodan_data, IPinfo_data, AV_data, BE_data, rec_output)


def gather_Shodan(target):
   
    Shodan_url = f"https://api.shodan.io/shodan/host/{target}?key={Shodan_API_KEY}"
    response = requests.get(Shodan_url)

    if(response.status_code != 200):
        return response.text

    return response.json()


def gather_IPinfo(target):

    IPinfo_url = f"https://ipinfo.io/{target}/json?token={IPinfo_token}"
    response = requests.get(IPinfo_url)

    return response.json()

def gather_BE(target):

    BE_url = f"https://api.binaryedge.io/v2/query/ip/{target}" # you can use ip/historical/{target} if you want the historical data of a target
    response = requests.get(BE_url, headers={'X-Key': BE_API_KEY})

    return response.json()

def gather_AV(target): # AlienVault OTX // No API key needed 

    AV_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{target}/general"

    response = requests.get(AV_url)

    return response.json() 


def run_whatweb(target):

    results = []

    try:
        # Run WhatWeb with JSON output
        result = subprocess.run(
            ["whatweb", "--log-json=-", "https://" + target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if result.returncode == 0:
            # Parse JSON output
            whatweb_output = result.stdout.strip()
		
            for line in whatweb_output.splitlines():
                try:
                    results.append(json.loads(line))
                    break  # Successfully parsed JSON
                except json.JSONDecodeError:
                    continue  # Ignore non-JSON lines
                
            return results
        else:
            return {"error": f"Error running WhatWeb: {result.stderr.strip()}"}
    except Exception as e:
        return {"error": f"Exception occurred: {str(e)}"}


def AI_analysis(json_data):
    API_Mod_URL = "https://api-inference.huggingface.co/models/mistralai/Mistral-Nemo-Instruct-2407"  # Replace with your chosen model's API URL
    headers = {"Authorization": f"Bearer {HF_Token}"}  

    AI_prompt = f"You are a security researcher, you will be given JSON data and you will analyze the data and point out any security concerns within the data. Be proficient and critical. Here is a JSON data: {json_data} ENDEND "
    
    payload = {
        "inputs": AI_prompt
    }
    
    
    response = requests.post(API_Mod_URL, headers=headers, json=payload)

    if(response.status_code != 200):
        return response.text

    response = response.json()
    result = response.pop()["generated_text"]

    return result.split("ENDEND", 1)[1].lstrip() # for some reason hugginface modules return the input prompt with the AI responce, thus I added the ENDEND keyword and stripped it 


def run_recon_ng(target):

    try:

        modules = [ # all the recon modules that do not requare keys or dependencies. // add modules as needed
                "recon/domains-hosts/google_site_web",
                "recon/domains-vulnerabilities/securitytrails",
                "recon/domains-hosts/netcraft",
                "recon/companies-contacts/pen",
                "recon/domains-vulnerabilities/xssed"
            ]

        with open(f"sc.txt", "w") as script_file: # creating the script file that has all the command that recon-ng will run , add commands as needed
            script_file.write("workspaces create example_workspace1\n")

            for mod in modules: # installing all the recon modules that do not requare keys or dependencies. 
                script_file.write(f"marketplace install {mod}\n")
                script_file.write(f"modules load {mod}\n")

                match mod:
                    case 'recon/repositories-vulnerabilities/gists_search':
                        script_file.write(f"options set SOURCE https://{target}\n")
                    case 'recon/ports-hosts/ssl_scan':
                        script_file.write(f"options set SOURCE {target}:443\n")
                    case _:
                        script_file.write(f"options set SOURCE {target}\n")
                                    

                script_file.write("run\n")
                script_file.write("back\n")
                    
            script_file.write("marketplace install reporting\n")
            script_file.write("modules load reporting/html\n")
            script_file.write(f"options set FILENAME {Path.cwd()}/{target}_recon-g_report.html\n")
            script_file.write(f"options set CUSTOMER {target}\n")
            script_file.write("options set CREATOR exmaple_user\n")
            script_file.write("run\n")
            script_file.write("back\n")
            script_file.write("workspaces remove example_workspace1\n")
            script_file.write("exit\n")

        
        result = subprocess.run(
            f"recon-ng -r {Path.cwd()}/sc.txt",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Process the output
        output = result.stdout.strip()
        error = result.stderr.strip()
        # print(error) # debugging
        
        os.remove("sc.txt")

        return {"output": output if output else "No output", "error": error if error else "No errors"}
    except Exception as e:
        return {"error": f"Exception occurred: {str(e)}"}

 
def resolve_hostname(target):
    try:
        ip_address = socket.gethostbyname(target)
        return ip_address
    except socket.gaierror:
        return None


def isDomain(input):
    return bool(re.match(r'^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$', input))


def isInvalidInput(input):
    
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', input):  # IPv4 pattern
        return False
    elif re.match(r'^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$', input):  # Domain pattern
        return False

    return True


def generate_report(target, osint1, osint2, osint3, osint4, osint5 , recon):

    report = {
        "target": target,
        "WhatWeb Data": osint1,
        "Shodan Data": osint2,
        "IPinfo Data": osint3,
        "AlienVault Data": osint4,
        "BinaryEdge Data": osint5,
        "recon-ng results": recon,
        "AI anylesis": f"see {target}_AI_analysis.txt",
    }

    print("Working on AI analysis...")
    ai = AI_analysis(osint2) # I only gave the AI the Shodan data due the limitation of the model.

    # ai = AI_analysis(json.dumps(report, indent=4)) # if you want to give the AI the whole report (make sure to pick a module that can handle it).
    print("AI analysis: Done.")
    
    with open(f"{target}_AI_analysis.txt", "w") as file:
        file.write(ai)


    with open(f"{target}_report.json", "w") as file:
        json.dump(report, file, indent=4)


    print(f"Report generated: {target}_report.json")
    

if __name__ == "__main__":
    target = args.target

    if(isInvalidInput(target)):
        print("invalid input, kindly Enter a domain or IP address")
        exit()

    main(target)