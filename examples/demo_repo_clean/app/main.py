"""Clean baseline: vulnerable deps pinned but never invoked.

Both pyyaml and requests appear in requirements.txt. Neither yaml.load nor
requests.get is ever called from any entrypoint. reachable-cve should report
zero reachable findings here.
"""


def main():
    print("hello, world")


if __name__ == "__main__":
    main()
