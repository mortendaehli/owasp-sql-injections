import requests
from requests import Response
from pathlib import Path
from typing import Optional, List, Dict, Any
from bs4 import BeautifulSoup
from bs4.element import PageElement
from html5print import HTMLBeautifier
from urllib.parse import urljoin
from pydantic import BaseModel, AnyHttpUrl
from owasp_sql_injections.config import config


DEFAULT_INJECTION_PAYLOAD = ["\"", "'", "' or True --", ""]


class Target(BaseModel):
    url: AnyHttpUrl


class SQLInjectionSession:

    def __init__(
            self,
            user_agent: Optional[str] = None
    ) -> None:
        self.user_agent = user_agent

        if not self.user_agent:
            self.user_agent = config.user_agent

        self.session: requests.Session = requests.Session()
        self.session.headers["User-Agent"] = user_agent

    def run_form_injector(self, payload: dict, target: Target) -> None:
        response = self.session.post(url=target.url, json=payload)
        print(response.text)

    def run_scanner(self, target: Target, payload: Optional[List[str]] = None) -> None:
        # Test directly in url:
        for injection_character in payload:
            injection_url = f"{target.url}{injection_character}"
            result: Response = self.session.get(injection_url)
            if result:
                if self.is_vulnerable(result):
                    print("[+] SQL Injection vulnerability detected, link:", injection_url)

        # test on HTML forms
        page_source = self.session.get(target.url).content.decode().lower()
        soup = BeautifulSoup(page_source, features="html5lib")
        forms = soup.find_all("form")

        print(f"[+] Detected {len(forms)} forms on {target.url}.")
        for form in forms:
            form_details = self.get_form_details(form=form)
            for injection_character in payload:
                data = dict()
                for input_tag in form_details["inputs"]:
                    if input_tag["type"] == "hidden" or input_tag["value"]:
                        data[input_tag["name"]] = input_tag["value"] + injection_character
                    elif input_tag["type"] != "submit":
                        data[input_tag["name"]] = f"test{injection_character}"

                url = urljoin(target.url, form_details["action"])
                if form_details["method"] == "post":
                    result: Response = self.session.post(url, data=data)
                elif form_details["method"] == "get":
                    result: Response = self.session.get(url, params=data)
                else:
                    continue

                if self.is_vulnerable(result):
                    print("[+] SQL Injection vulnerability detected, link:", url)
                    print("[+] Form:")
                    print(HTMLBeautifier.beautify(form_details))
        return None

    @staticmethod
    def get_form_details(form: PageElement) -> Dict[str, Any]:
        """
        This function extracts all possible useful information about an HTML `form`
        """
        details = {}

        actions = form.attrs.get("action").lower()
        methods = form.attrs.get("method", "get").lower()
        inputs = list()
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            inputs.append({"type": input_type, "name": input_name, "value": input_value})

        details["action"] = actions
        details["method"] = methods
        details["inputs"] = inputs
        return details

    @staticmethod
    def is_vulnerable(response: Response) -> bool:
        errors = {
            "you have an error in your sql syntax;",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "SQLITE_ERROR"
        }
        for error in errors:
            if error in response.text.lower():
                return True
        return False


