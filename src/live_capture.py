import subprocess
from pathlib import Path
from datetime import datetime


def capture_live_traffic(interface="5", duration=30):
    """
    Capture network traffic using TShark.
    """

    capture_folder = Path("captures")
    capture_folder.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    output_file = capture_folder / f"live_{timestamp}.pcapng"

    command = [
        "tshark",
        "-i", str(interface),
        "-a", f"duration:{duration}",
        "-w", str(output_file)
    ]

    print(f"Capturing traffic for {duration} seconds...")

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=duration + 20
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Capture failed: {result.stderr}"
        )

    print(f"Capture saved to: {output_file}")

    return str(output_file)


if __name__ == "__main__":
    capture_live_traffic()