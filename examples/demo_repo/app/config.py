"""Loads a config file. Uses the *vulnerable* yaml.load — REACHABLE."""
import yaml


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.load(f)  # CVE-2020-14343 sink


def main():
    cfg = load_config("config.yml")
    print(cfg)


if __name__ == "__main__":
    main()
