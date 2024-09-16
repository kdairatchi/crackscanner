import requests
from bs4 import BeautifulSoup

def check_api():
    """Check API accessibility with a dummy request."""
    url = "https://services.nvd.nist.gov/rest/json/cves/1.0?resultsPerPage=1"  # Example URL to test access
    response = requests.get(url)
    if response.status_code == 200:
        return True
    else:
        print(f"Failed to check API access. Status code: {response.status_code}")
        return False

def get_exploits_from_exploitdb():
    """Fetch exploits from Exploit-DB."""
    url = "https://www.exploit-db.com/"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Example: Get the first 5 exploit entries from the main page
        exploits = []
        for entry in soup.find_all('article', class_='exploit-item', limit=5):
            id = entry.find('a', class_='title').get('href').split('/')[-1]
            name = entry.find('a', class_='title').text.strip()
            description = entry.find('div', class_='description').text.strip()
            exploit_url = "https://www.exploit-db.com" + entry.find('a', class_='title').get('href')
            
            exploits.append({
                "id": id,
                "name": name,
                "description": description,
                "exploit": exploit_url
            })
        return exploits
    else:
        print(f"Failed to fetch data from Exploit-DB. Status code: {response.status_code}")
        return []

def get_exploits_from_nvd():
    """Fetch CVEs from the NVD search endpoint."""
    url = "https://services.nvd.nist.gov/rest/json/v2/cve"
    params = {
        'resultsPerPage': 5  # Number of results to retrieve (change as needed)
    }
    response = requests.get(url, params=params)

    if response.status_code == 200:
        try:
            data = response.json()
            # Extract relevant data from the response JSON
            exploits = [
                {
                    "id": item["cve"]["CVE_data_meta"]["ID"],
                    "name": item["cve"]["description"]["description_data"][0]["value"],
                    "description": item["cve"]["description"]["description_data"][0]["value"],
                    "exploit": "Refer to NVD for details"  # Placeholder for actual exploit link
                }
                for item in data.get("CVE_Items", [])
            ]
            return exploits
        except requests.exceptions.JSONDecodeError:
            print("Error decoding JSON response.")
            return []
    else:
        print(f"Failed to fetch exploits. Status code: {response.status_code}")
        return []

def main():
    # Ask user for the API source
    print("Select the API source:")
    print("1. Exploit-DB")
    print("2. NVD")
    choice = input("Enter the number (1 or 2): ")

    if choice == "1":
        print("Fetching data from Exploit-DB...")
        exploits = get_exploits_from_exploitdb()
        if exploits:
            for exploit in exploits:
                print(f"ID: {exploit['id']}")
                print(f"Name: {exploit['name']}")
                print(f"Description: {exploit['description']}")
                print(f"Exploit URL: {exploit['exploit']}")
                print("-" * 50)  # Separator between exploits
        else:
            print("No exploits found on Exploit-DB or there was an error fetching the data.")
    
    elif choice == "2":
        if check_api():
            print("API is accessible")
            print("Fetching data from NVD...")
            exploits = get_exploits_from_nvd()
            if exploits:
                for exploit in exploits:
                    print(f"ID: {exploit['id']}")
                    print(f"Name: {exploit['name']}")
                    print(f"Description: {exploit['description']}")
                    print(f"Exploit: {exploit['exploit']}")
                    print("-" * 50)  # Separator between exploits
            else:
                print("No exploits found in NVD or there was an error fetching the data.")
        else:
            print("API access is invalid or failed")
    
    else:
        print("Invalid choice. Please enter 1 or 2.")

if __name__ == "__main__":
    main()