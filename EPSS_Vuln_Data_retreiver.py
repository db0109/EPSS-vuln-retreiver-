#!/usr/bin/python3

import requests

def get_epss_score(cve):
    url = f"https://api.first.org/data/v1/epss?cve={cve}"

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        if 'data' in data and len(data['data']) > 0:
            epss_score = data['data'][0].get('epss')

            if epss_score is not None:
                percentage = float(epss_score) * 100
                print(f"EPSS score for {cve}: {epss_score} ({percentage:.2f}%)")
            else:
                print(f"No EPSS score available for {cve}")
        else:
            print(f"No data available for {cve}")

    except requests.exceptions.RequestException as e:
        print(f"Error occurred: {e}")

# Example usage:
cves = ["CVE-2021-44228", "CVE-2022-12345", "CVE-2023-67890"]

for cve in cves:
    get_epss_score(cve)