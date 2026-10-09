from datetime import datetime

from app.tools.query_evidence import load_evidence


def correlate_case():
    evidence = load_evidence()

    usb_events = [
        item
        for item in evidence
        if item["artifact_type"] == "usb_connection"
    ]

    file_events = [
        item
        for item in evidence
        if item["artifact_type"] == "file_access"
    ]

    correlations = []

    for file_event in file_events:
        file_time = datetime.fromisoformat(
            file_event["timestamp"].replace("Z", "+00:00")
        )

        for usb_event in usb_events:

            usb_time = datetime.fromisoformat(
                usb_event["timestamp"].replace("Z", "+00:00")
            )

            # USB connection before file access
            if (
                usb_event["action"] == "connected"
                and usb_time <= file_time
            ):
                disconnect_events = [
                    event
                    for event in usb_events
                    if (
                        event["action"] == "disconnected"
                        and event["object"] == usb_event["object"]
                    )
                ]

                still_connected = True

                if disconnect_events:
                    disconnect_time = datetime.fromisoformat(
                        disconnect_events[0]["timestamp"]
                        .replace("Z", "+00:00")
                    )

                    still_connected = file_time <= disconnect_time

                correlations.append(
                    {
                        "type": "temporal",
                        "relationship": (
                            "USB connected before file access"
                        ),
                        "usb_evidence_id": usb_event["evidence_id"],
                        "file_evidence_id": file_event["evidence_id"],
                        "usb_device": usb_event["object"],
                        "file": file_event["object"],
                        "file_access_while_connected": still_connected,
                    }
                )

    return correlations