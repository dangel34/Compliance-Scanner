
def clear_all_caches() -> None:
    """
    Clear the subprocess result cache in every custom-function module.

    Call this once at the start of each scan session so that re-scans from
    the GUI (or repeated CLI invocations in the same process) always execute
    fresh commands rather than returning stale cached results.
    """
    from core.custom_functions import (
        access_control,
        audit_accountability,
        configuration_management,
        identification_authentication,
        system_communications_protection,
        system_information_integrity,
    )
    for mod in (
        access_control,
        audit_accountability,
        configuration_management,
        identification_authentication,
        system_communications_protection,
        system_information_integrity,
    ):
        mod.clear_cache()
