import ipaddress
from dataclasses import dataclass


class ValidationScopeError(ValueError):
    """Raised when a validation target is outside the local lab scope."""


@dataclass(frozen=True)
class ValidationTarget:
    host: str
    port: int = 25565
    purpose: str = "local validation"

    def __post_init__(self) -> None:
        if not 1 <= self.port <= 65535:
            raise ValidationScopeError("validation target port must be between 1 and 65535")
        if not _is_lab_host(self.host):
            raise ValidationScopeError(
                "public server targeting is out of scope; use localhost or a private lab address"
            )

    @property
    def is_local(self) -> bool:
        host = self.host.lower()
        if host == "localhost":
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False


@dataclass(frozen=True)
class ValidationPlan:
    mode: str
    target: ValidationTarget
    mod_id: str
    version: str
    safety_controls: tuple[str, ...]


def build_validation_plan(target: ValidationTarget, *, mod_id: str, version: str) -> ValidationPlan:
    return ValidationPlan(
        mode="local_validation",
        target=target,
        mod_id=mod_id,
        version=version,
        safety_controls=(
            "non-exploit",
            "owner-authorized target only",
            "no public server discovery",
            "no proof-of-concept payload generation",
        ),
    )


def _is_lab_host(host: str) -> bool:
    normalized = host.strip().lower()
    if normalized == "localhost":
        return True
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return address.is_loopback or address.is_private
