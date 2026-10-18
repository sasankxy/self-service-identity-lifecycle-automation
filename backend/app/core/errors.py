from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.core.cookies import clear_auth_cookies


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, headers: dict | None = None, fields: dict | None = None,
                 clear_cookies: bool = False):
        self.clear_cookies = clear_cookies
        self.status, self.code, self.message, self.headers, self.fields = status, code, message, headers, fields


def _body(code: str, message: str, fields: dict | None = None) -> dict:
    err = {"code": code, "message": message}
    if fields:
        err["fields"] = fields
    return {"error": err}


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError):
        resp = JSONResponse(_body(exc.code, exc.message, exc.fields), status_code=exc.status, headers=exc.headers)
        if exc.clear_cookies:
            clear_auth_cookies(resp, request.app.state.settings)
        return resp

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError):
        fields: dict[str, str] = {}
        for e in exc.errors():
            loc = [str(p) for p in e["loc"] if p not in ("body", "query")]
            msg = e["msg"].removeprefix("Value error, ")
            fields[".".join(loc) or "_"] = msg
        return JSONResponse(_body("validation_error", "Please correct the highlighted fields.", fields), status_code=422)
