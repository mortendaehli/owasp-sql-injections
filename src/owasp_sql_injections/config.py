from pydantic import BaseModel


class Config(BaseModel):
    user_agent: str = \
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_0_1)" \
        " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"


config = Config()  # Base config
