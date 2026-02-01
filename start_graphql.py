import uvicorn

if __name__ == "__main__":
    print("Starting Cheat-Me GraphQL Feature Server...")
    uvicorn.run("server.main:app", host="0.0.0.0", port=8085, reload=True)
