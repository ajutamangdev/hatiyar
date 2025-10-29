from pydantic import BaseModel


class GlobalConfig(BaseModel):
    sandbox_enabled: bool = False
    dry_run: bool = True
