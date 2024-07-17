import os
import re

def print_colored(text, color):
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "end": "\033[0m",
    }
    print(f"{colors[color]}{text}{colors['end']}")

def scan_findings_for_sensitive_info(findings_dir, sensitive_strings):
    results = {}
    apk_analysed = False

    for findings_file in os.listdir(findings_dir):
        if findings_file.endswith("_findings.txt"):
            apk_analysed = True
            findings_path = os.path.join(findings_dir, findings_file)
            with open(findings_path, 'r', encoding='utf-8') as file:
                findings_content = file.read()

            no_findings_pattern = "No findings matching the patterns were found."
            if no_findings_pattern in findings_content:
                apk_name = findings_file.replace("_findings.txt", "")
                print_colored(f"[!] {apk_name} - Not able to statically analyse,kindly perform dynamic analysis .", "red")
                continue

            sensitive_info_found = False
            for sensitive_str in sensitive_strings:
                pattern = re.compile(sensitive_str, re.IGNORECASE)
                matches = pattern.findall(findings_content)
                if matches:
                    sensitive_info_found = True
                    if findings_file not in results:
                        results[findings_file] = {}
                    if sensitive_str not in results[findings_file]:
                        results[findings_file][sensitive_str] = len(matches)

            if not sensitive_info_found:
                apk_name = findings_file.replace("_findings.txt", "")
                print_colored(f"[!] {apk_name} - No sensitive things found.", "yellow")

    if apk_analysed:
        for apk, findings in results.items():
            print_colored(f"\nFile: {apk}", "cyan")
            for sensitive_str, count in findings.items():
                # Removing regex syntax from the sensitive string
                sensitive_str_clean = sensitive_str.lstrip(r'\b').rstrip(r'\b').replace(r'_', ' ')
                print_colored(f"  [+] Sensitive String: {sensitive_str_clean} - Occurrences: {count}", "green")
    else:
        print_colored("[-] No APK findings to analyze.", "red")

sensitive_strings = [
    r"\bIMEI\b", r"\bandroidid\b", r"\bssid\b", r"\bimsi\b",
    r"\busername\b", r"\bgps\b", r"\bserialnumber\b", r"\bemail\b",
    r"\bssid\b", r"\bbssid\b",
    r"\bmac\b", r"\bactivity_name\b",
    r"\bmanufacturer\b",
    r"\bos_version\b", r"\bapp_url\b",
    r"\badvertising_id\b", r"\bcell_id\b", r"\bcell_info\b",
    r"\bssn\b", r"\bcredit_card_number\b",
    r"\bcrypto_wallet\b", r"\bhealth_data\b",
    r"\bfacial_recognition\b", r"\bconnection_type\b",
    r"\bversion_name\b", r"\bwifi_config\b", r"\bvpn_settings\b",
    r"\buser_preferences\b", r"\bsearch_history\b",r"\bcaller-number\b",r"\buser-phone-number\b",r"\buser_phone_number\b",r"\bphone_number\b",r"\bphone-number\b",
    r"\bbrowser_history\b",
    r"\bapplist\b",r"\bapp_list\b",r"\appinstall\b",r"\app_install\b",
    "bank_account","search_history","searchhistory","phone_number",
    "OAID","AAID","VAID","androidid"
]


# Example usage
findings_directory = 'findings'
scan_findings_for_sensitive_info(findings_directory, sensitive_strings)
