from fastapi import FastAPI, Response, status

from src.api.database import database_status

app = FastAPI(
    title="HoneyTrace AI API",
    description="Read-only API for normalized security events and incidents.",
    version="0.1.0",
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/db")
def health_db(response: Response) -> dict[str, str]:
    result = database_status()
    if result != "ok":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": result}