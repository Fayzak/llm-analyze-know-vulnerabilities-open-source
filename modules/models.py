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


class PromptDataModel(BaseModel):
    cve_id: str
    kev_status: bool
    epss: float | None = None
    base_score: float
    severity: str
    nvd_details: dict | None = None
    github_details: list[dict] | None = None
