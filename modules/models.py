from pydantic import BaseModel


class EPSSRecord(BaseModel):
    cve: str
    epss: float
    percentile: float
    date: str


class EPSSResponse(BaseModel):
    status: str
    data: list[EPSSRecord]
    message: str | None = None
    total: int | None = None
