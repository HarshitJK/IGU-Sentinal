"""Loopback exported-flow streaming benchmark through UDP ingest and disk append.

Includes sender scheduling, socket buffering, validation, inference and alert
append. Excludes packet capture/extraction, fsync and browser rendering. No
network probes: generated FlowRecord datagrams go only to 127.0.0.1.
"""
import argparse
import asyncio
from datetime import datetime
import json
from pathlib import Path
import platform
import os
import socket
import threading
import time


def percentile(values, quantile):
    if not values:
        return None
    return sorted(values)[min(len(values) - 1, int(quantile * (len(values) - 1)))]


async def run(rate, duration, output):
    output.mkdir(parents=True, exist_ok=True)
    log_path = output / 'alerts.jsonl'
    if log_path.exists():
        raise ValueError('Use a fresh output directory; existing alerts are preserved')
    os.environ['IGU_ALERT_LOG_PATH'] = str(log_path)
    os.environ['IGU_UDP_BIND'] = '127.0.0.1'
    from igu_sentinel import api
    from igu_sentinel.schemas import FlowRecord
    record_path = Path(__file__).resolve().parents[2] / 'tests/fixtures/volumetric_ddos_sample.jsonl'
    template = FlowRecord.model_validate_json(record_path.read_text().splitlines()[0])
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    sent_at, latencies = {}, []
    original_log = api.log_alert
    def measured_log(alert):
        result = original_log(alert)
        timestamp = sent_at.get(alert.flow_id)
        if timestamp is not None:
            latencies.append((time.perf_counter() - timestamp) * 1000)
        return result
    api.log_alert = measured_log
    controller = api.CaptureController()
    controller.start(f'udp:{port}', 120, asyncio.get_running_loop())
    sender_errors = []
    count = int(rate * duration)
    send_elapsed = [0.0]
    def send():
        started = time.perf_counter()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                for index in range(count):
                    remaining = started + index / rate - time.perf_counter()
                    if remaining > 0:
                        time.sleep(remaining)
                    flow = template.model_copy(update={'flow_id': f'benchmark-{index}', 'timestamp': datetime.now()})
                    data = flow.model_dump_json().encode()
                    sent_at[flow.flow_id] = time.perf_counter()
                    sock.sendto(data, ('127.0.0.1', port))
        except Exception as exc:
            sender_errors.append(str(exc))
        send_elapsed[0] = time.perf_counter() - started
    try:
        await asyncio.sleep(.25)
        if not controller.is_running():
            raise RuntimeError(controller.snapshot())
        thread = threading.Thread(target=send)
        thread.start()
        while thread.is_alive():
            await asyncio.sleep(.1)
        await asyncio.to_thread(thread.join)
        deadline = time.monotonic() + 5
        while controller.state['flows_scored'] < len(sent_at) and time.monotonic() < deadline:
            await asyncio.sleep(.1)
        await asyncio.to_thread(controller.stop)
        state = controller.snapshot()
    finally:
        await asyncio.to_thread(controller.stop)
        api.log_alert = original_log
    report = {'scope': __doc__, 'python': platform.python_version(), 'machine': platform.machine(),
              'cpu_count': os.cpu_count(), 'target_flows_per_second': rate, 'target_duration_seconds': duration,
              'sender_elapsed_seconds': send_elapsed[0], 'actual_send_rate': len(sent_at) / send_elapsed[0],
              'sent': len(sent_at), 'unscored': len(sent_at) - state['flows_scored'], 'capture': state,
              'sender_errors': sender_errors, 'latency_samples': len(latencies),
              'send_to_append_ms': {'p50': percentile(latencies, .50), 'p95': percentile(latencies, .95),
                                    'p99': percentile(latencies, .99), 'max': max(latencies, default=None)}}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    if sender_errors or state.get('error') or report['unscored']:
        raise SystemExit('Benchmark did not sustain the requested load without errors/drops')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rate', type=int, default=200)
    parser.add_argument('--duration', type=float, default=10)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.rate <= 0 or args.duration <= 0 or args.rate * args.duration > 100000:
        parser.error('Require positive rate/duration with at most 100000 records per run')
    asyncio.run(run(args.rate, args.duration, args.output))


if __name__ == '__main__':
    main()
