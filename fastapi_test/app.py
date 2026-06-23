from fastapi import FastAPI
import yaml

app = FastAPI()

@app.get("/")
def root():
    return yaml.load("a: 1")