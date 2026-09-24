def get_security_status(
    high,
    medium,
    low
):
    if high > 0:
        return (
            "🔴",
            "High Exposure",
            "High-risk services were detected."
        )

    if medium > 0:
        return (
            "🟠",
            "Moderate Exposure",
            "Some services require security review."
        )

    if low > 0:
        return (
            "🟢",
            "Low Exposure",
            "No predefined high-risk services were detected."
        )

    return (
        "⚪",
        "No Open Services",
        "No open ports were detected."
    )