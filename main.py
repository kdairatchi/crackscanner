import requests
 
def check_api(api_key):
    url = "https://api.example.com/v1/check"
    headers = {"Authorization": f"Bearer {api_key}"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return True
    else:
        return False
 
def get_exploits(api_key):
    url = "https://api.example.com/v1/exploits"
    headers = {"Authorization": f"Bearer {api_key}"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return []
 
def main():
    api_key = input("Enter your API key: ")
    if check_api(api_key):
        print("API key is valid")
        exploits = get_exploits(api_key)
        for exploit in exploits:
            print(exploit)
    else:
        print("API key is invalid")
 
if __name__ == "__main__":
    main()