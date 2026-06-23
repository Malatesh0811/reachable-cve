import yaml

class Loader:
    def __init__(self):
        self._load = yaml.load

    def run(self, data):
        return self._load(data)

def main():
    Loader().run("a: 1")

main()