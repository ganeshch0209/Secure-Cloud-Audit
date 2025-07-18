import json
import os
from datetime import datetime
from modules import nsg_scanner

def load_config():
    with open('config.json') as f:
        return json.load(f)

def main():
    config = load_config()
    print("✅ Configuration loaded.")

    # Run NSG scan
    nsg_findings = nsg_scanner.scan_nsgs(config)

    # Output report
    timestamp = datetime.now().strftime("%Y_%m_%d_%H%M")
    report_file = os.path.join(config["report_path"], f"nsg_report_{timestamp}.csv")
    os.makedirs(config["report_path"], exist_ok=True)
    
    nsg_scanner.export_to_csv(nsg_findings, report_file)
    print(f"✅ NSG scan complete. Report saved to {report_file}")

if __name__ == "__main__":
    main()
