from fastapi import FastAPI
from strawberry.fastapi import GraphQLRouter
from contextlib import asynccontextmanager
from .db import database
from .schema import schema

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Connect to database on startup
    await database.connect()
    yield
    # Disconnect on shutdown
    await database.disconnect()

app = FastAPI(title="Cheat-Me GraphQL Feature Server", lifespan=lifespan)

graphql_app = GraphQLRouter(schema)
app.include_router(graphql_app, prefix="/graphql")

@app.get("/")
async def root():
    return {"message": "Cheat-Me GraphQL Server is running. Visit /graphql for the playground."}
