import os
import re
import subprocess
import sys

def decompile_apk_with_jadx(apk_path, output_dir_name):
    cwd = os.getcwd()
    full_output_dir = os.path.join(cwd, output_dir_name, "java_sources")
    full_apk_path = os.path.join(cwd, apk_path)
    os.makedirs(full_output_dir, exist_ok=True)

    jadx_command = f"jadx -d {full_output_dir} {full_apk_path}"
    subprocess.run(jadx_command, shell=True)
    print(f"Decompilation complete. Java source code is in: {full_output_dir}")

    return full_output_dir

def find_patterns_in_method(java_code, patterns):
    method_regex = r'((public|private|protected)\s+)?[a-zA-Z\<\>\[\]]+\s+[a-zA-Z0-9_]+\(.*?\)\s*\{'
    method_ranges = []

    for match in re.finditer(method_regex, java_code, re.DOTALL):
        start, brace_count = match.start(), 1
        for i in range(match.end(), len(java_code)):
            if java_code[i] == '{':
                brace_count += 1
            elif java_code[i] == '}':
                brace_count -= 1
            if brace_count == 0:
                method_ranges.append((start, i + 1))
                break

    findings = []
    for start, end in method_ranges:
        method_body = java_code[start:end]
        for pattern in patterns:
            if re.search(pattern, method_body):
                findings.append((method_body, pattern))
                break

    return findings

def scan_java_files(output_dir, patterns):
    findings = []
    for root, _, files in os.walk(output_dir):
        for file in files:
            if file.endswith(".java"):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    java_code = f.read()
                    file_findings = find_patterns_in_method(java_code, patterns)
                    if file_findings:
                        findings.extend([(file_path, finding) for finding in file_findings])

    return findings

def scan_apks_in_directory(directory, patterns, findings_dir):
    os.makedirs(findings_dir, exist_ok=True)

    for item in os.listdir(directory):
        if item.endswith(".apk"):
            apk_path = os.path.join(directory, item)
            output_dir_name = item + "_Out"
            full_output_dir = decompile_apk_with_jadx(apk_path, output_dir_name)

            all_findings = scan_java_files(full_output_dir, patterns)

            findings_file_path = os.path.join(findings_dir, f"{item}_findings.txt")
            with open(findings_file_path, 'w', encoding='utf-8') as findings_file:
                if all_findings:
                    for file_path, (finding, pattern) in all_findings:
                        findings_file.write(f"In file: {file_path}\nPattern: {pattern}\n{finding}\n\n")
                else:
                    findings_file.write("No findings matching the patterns were found.")

            print(f"Findings for {item} written to {findings_file_path}")


def main():
    directory_to_scan = sys.argv[1]
    patterns_to_search = [
    # Methods that involve sending data with common HTTP client libraries, focused on GET and POST requests
    r"\b(?:\.get\(|\.post\()\b.*?(\.url\(|\.uri\()",
    r"\b(?:\.get\(|\.post\()\b.*?(\.build\(\)|\.execute\(\))",
    
    # Patterns for HTTP client libraries
    r"\bHttpClient\b.*?\.execute\(",
    r"\bHttpURLConnection\b.*?\.connect\(",
    r"\bOkHttpClient\b.*?(\.newCall\(|\.execute\()",
    r"\bRetrofit\b.*?(\.create\(|\.call\()",

    r"new CloudRequestHandler\(",  # Instantiation of CloudRequestHandler
    r"new OkHttpClient\(\)\.newCall",  # OkHttp
    r"new Retrofit\.Builder\(\)",  # Retrofit
    r"new StringRequest\(",  # Volley
    r"new DefaultHttpClient\(\)",  # Apache HttpClient
    r"new WebSocket\(",  # Websockets
    r"new Request\.Builder\(\)"
    
    # matching for variable names that could contain sensitive information
    r"\burl\b|\buri\b|\bendpoint\b|\bapi\b|\bpath\b",
    
    # Matching onResponse and onFailure
    r"\bonResponse\((Call<|Response<)",
    r"\bonFailure\(Call<",
    
    # Narrow down AsyncTask pattern
    r"\bextends AsyncTask<Params, Progress, Result>",
    
    # More specific WebSocket patterns
    r"\bnew WebSocket\b|\bWebSocket\.Listener\b",
    
    # user identification or device information
    r"\.addHeader\(\"(Authorization|User-Agent|Device-ID|API-Key|Session-Token)\"",
    r"\.setHeader\(\"(Authorization|User-Agent|Device-ID|API-Key|Session-Token)\"",
    
    r"new Retrofit.Builder\(\).baseUrl\(",
    ]
    findings_directory = 'findings'
    scan_apks_in_directory(directory_to_scan, patterns_to_search, findings_directory)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: full_static_scan.py <apk directory>")
        sys.exit(1)

    else:
        main()


