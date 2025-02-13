
# 🔍 OSINTAI

**OSINTAI** is an automated reconnaissance tool that gathers **publicly available data** about a target (domain/IP). It utilizes various public data sources such as **Shodan**, **BinaryEdge** and others to extract valuable insights and detect through **AI Analysis** potential security concerns.

---

## Features

- **Automated OSINT gathering.**  
- **Multiple Data Sources.**  
- **AI Analysis.**  
- **Passive scanning meaning there is no actual hits on the target.** 
- **Highly customizable tool.**
- **JSON Reporting.**   

---

## ️Requirements

###  **Adding API KEYs**
Modify the Follwing lines to add the API KEYs:
```bash
Shodan_API_KEY = "SHODAN_API_KEY"
IPinfo_token = "IPinfo_TOKEN"
BE_API_KEY = "BinaryEdge_API_KEY"
HF_Token = "HugginFace_TOKEN" 
```

###  **(Optional) Add or change API calls**
#### 🔹 **Shodan**
```bash
Shodan_url = f"https://api.shodan.io/shodan/host/{target}?key={Shodan_API_KEY}"
```

#### 🔹 **IPinfo**
```bash
IPinfo_url = f"https://ipinfo.io/{target}/json?token={IPinfo_token}"
```

#### 🔹 **BinaryEdge**
```bash
BE_url = f"https://api.binaryedge.io/v2/query/ip/{target}"

```

#### 🔹 **AlienVault OTX // No API key needed**
```bash
AV_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{target}/general"

```
### **(Optional) AI modification**
#### 🔹 **AI module, Replace with your chosen model's API URL (make sure it has a large input tokens)**
```bash
API_Mod_URL = "https://api-inference.huggingface.co/models/mistralai/Mistral-Nemo-Instruct-2407" 

```

#### 🔹 **AI Prompt**
```bash
    AI_prompt = f"You are a security researcher, you will be given JSON data and you will analyze the data and point out any security concerns within the data. Be proficient and critical. Here is a JSON data: {json_data} ENDEND"

```


#### 🔹 **Add or remove recon-ng modules**
```bash
modules = [
                "recon/domains-hosts/google_site_web",
                "recon/domains-hosts/netcraft",
                "recon/companies-contacts/pen",
                "recon/domains-vulnerabilities/xssed"
                ...
            ]
```


---

## Usage

Run the tool with a target domain or IP:

```bash
python osintai.py -t <target>
```

If you wan to run recon-ng add the ```-re\--reconng``` flag (takes long time):

```bash
python osintai.py -t <target> --reconng
```



---

## Example

```bash
└─$ python osintai.py -t example.com
Starting assessment for: example.com - 192.168.1.2
Working on OSINT...
OSINT Data: Done.
Working on AI analysis...
AI analysis: Done.
Report generated: example.com_report.json

```
---

## Note  
AI-generated output significantly differ and may spits out garbage or useless result, as it is heavily based on the model and input prompt.

---

## TODO 
- Add more OSINT data sources  
- Improve AI classification  and generated output 

---

## License
This tool is intended for educational and authorized testing purposes only.

---
