import json
import ssl
import socket
import requests
from bs4 import BeautifulSoup
from datetime import datetime

INVENTORY = [
    {"id": "aashirvaad", "name": "Aashirvaad", "url": "https://aashirvaad.com"},
    {"id": "bingo", "name": "Bingo! Snacks", "url": "https://bingosnacks.com"},
    {"id": "candyman", "name": "Candyman", "url": "https://candymanclub.com"},
    {"id": "darkfantasy", "name": "Dark Fantasy Creations", "url": "https://darkfantasycreations.com"},
    {"id": "aashirvaad_dairy", "name": "Aashirvaad Dairy Delights", "url": "https://aashirvaaddairydelights.com"},
    {"id": "lets_live_young", "name": "Lets Live Young", "url": "https://letsliveyoung.in"},
    {"id": "sunrise_spices", "name": "Sunrise Spices", "url": "https://sunrisespices.in"},
    {"id": "foodies_only", "name": "Foodies Only", "url": "https://foodiesonly.in"},
    {"id": "family_like_friends", "name": "Family Like Friends", "url": "https://familylikefriends.com"},
    {"id": "lets_boing", "name": "Lets Boing", "url": "https://letsboing.com"},
    {"id": "fabelle", "name": "Fabelle", "url": "https://fabelle.in"},
    {"id": "right_shift", "name": "Right Shift", "url": "https://rightshift.in"},
    {"id": "sunfeast_wowzers", "name": "Sunfeast Wowzers", "url": "https://sunfeastwowzers.com"},
    {"id": "bnatural", "name": "B Natural", "url": "https://bnatural.in"},
    {"id": "kitchens_of_india", "name": "Kitchens of India", "url": "https://kitchensofindia.com"},
    {"id": "moms_magic", "name": "Sunfeast Mom's Magic", "url": "https://sunfeastmomsmagic.com"},
    {"id": "itc_gifting", "name": "ITC Gifting", "url": "https://itcgifting.com"},
    {"id": "yippee", "name": "Sunfeast YiPPee!", "url": "https://sunfeastyippee.com"},
    {"id": "itcportal", "name": "ITC Portal", "url": "https://itcportal.com"},
    {"id": "master_chef", "name": "ITC Master Chef", "url": "https://itcmasterchef.com"},
    {"id": "marie_light", "name": "Sunfeast Marie Light", "url": "https://sunfeastmarielight.com"},
    {"id": "fantastik", "name": "Sunfeast Fantastik", "url": "https://sunfeastfantastik.com"},
    {"id": "sunbean", "name": "Sunbean", "url": "https://sunbean.in"}
]

def scan_site(site):
    domain = site["url"].replace("https://", "").replace("http://", "").strip("/")
    checks = []
    
    # 1. SSL/TLS Check
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5.0)
            s.connect((domain, 443))
            checks.append({"id": 54, "cat": "Security", "name": "SSL / TLS Encryption", "s": "pass", "f": "HTTPS Active & Valid Certificate"})
    except Exception as e:
        checks.append({"id": 54, "cat": "Security", "name": "SSL / TLS Encryption", "s": "fail", "f": f"SSL Connection Issue: {str(e)}"})

    # 2. Content & Link Checks
    try:
        r = requests.get(site["url"], headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
        html = r.text.lower()
        soup = BeautifulSoup(r.text, 'html.parser')

        # Link to itcportal.com
        has_portal = any("itcportal.com" in a.get('href', '') for a in soup.find_all('a', href=True))
        checks.append({
            "id": 18, "cat": "UI/UX", "name": "Link to itcportal.com",
            "s": "pass" if has_portal or "itcportal" in domain else "fail",
            "f": "ITC portal backlink present" if has_portal or "itcportal" in domain else "Missing link to itcportal.com"
        })

        # Grievance / Privacy
        has_privacy = "privacy policy" in html or "terms" in html
        checks.append({
            "id": 50, "cat": "Governance", "name": "Terms & Privacy Policy",
            "s": "pass" if has_privacy else "fail",
            "f": "Mandatory policy links detected" if has_privacy else "Terms / Privacy policy missing"
        })

        # Legal Metrology
        has_mrp = "mrp" in html or "net quantity" in html or "inclusive of all taxes" in html
        checks.append({
            "id": 46, "cat": "Legal Metrology", "name": "Packaged Goods Disclosures",
            "s": "pass" if has_mrp else "warn",
            "f": "Legal metrology declarations visible" if has_mrp else "Declarations not explicitly detected"
        })
    except Exception as e:
        checks.append({"id": 0, "cat": "Network", "name": "Site Reachability", "s": "fail", "f": f"Could not reach website: {str(e)}"})

    return {
        "name": site["name"],
        "domain": domain,
        "division": "ITC Foods",
        "auditDate": datetime.utcnow().strftime("%d %b %Y"),
        "checks": checks
    }

def run():
    report = {}
    for item in INVENTORY:
        report[item["id"]] = scan_site(item)
    with open("audit_results.json", "w") as f:
        json.dump(report, f, indent=2)

if __name__ == "__main__":
    run()
