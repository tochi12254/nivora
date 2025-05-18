from app.services.monitoring.history import PacketSniffer
import time

if __name__ == "__main__":
    # Store logs in packets.jsonl
    sniffer = PacketSniffer(log_file="packets.jsonl")

    try:
        sniffer.start()
        print("Sniffer running. Press Ctrl+C to stop...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sniffer.stop()
        print("\nSniffer stopped. Data saved to packets.jsonl")
