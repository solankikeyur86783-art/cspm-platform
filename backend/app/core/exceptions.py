from fastapi import HTTPException, status


class CSPMException(Exception):
    def __init__(self, message: str, code: str = "CSPM_ERROR"):
        self.message = message
        self.code = code
        super().__init__(message)


class NotFoundException(CSPMException):
    def __init__(self, resource: str, id: str):
        super().__init__(f"{resource} '{id}' not found", "NOT_FOUND")


class UnauthorizedException(CSPMException):
    def __init__(self, message: str = "Authentication required"):
        super().__init__(message, "UNAUTHORIZED")


class ForbiddenException(CSPMException):
    def __init__(self, message: str = "Insufficient permissions"):
        super().__init__(message, "FORBIDDEN")


class ScanException(CSPMException):
    def __init__(self, message: str):
        super().__init__(message, "SCAN_ERROR")


class CloudProviderException(CSPMException):
    def __init__(self, provider: str, message: str):
        super().__init__(f"[{provider}] {message}", "CLOUD_PROVIDER_ERROR")


# FastAPI HTTP shortcuts
def http_not_found(resource: str, id: str = "") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"code": "NOT_FOUND", "message": f"{resource} {id} not found".strip()},
    )


def http_unauthorized(msg: str = "Not authenticated") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"code": "UNAUTHORIZED", "message": msg},
        headers={"WWW-Authenticate": "Bearer"},
    )


def http_forbidden(msg: str = "Forbidden") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={"code": "FORBIDDEN", "message": msg},
    )


def http_conflict(msg: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={"code": "CONFLICT", "message": msg},
    )
