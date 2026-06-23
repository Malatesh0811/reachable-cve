import yaml

load_fn = getattr(yaml, "load")

def main():
    load_fn("a: 1")

if __name__ == "__main__":
    main()