#!/bin/sh
# This entrypoint spawns python as a child process to exercise the
# sched_process_exec tracepoint. At initial reconcile only the shell
# (PID 1) is visible — it has no TLS symbols. When python starts,
# the exec tracepoint detects it in the tracked cgroup and notifies
# userspace to attach uprobes.

echo "entrypoint: waiting before launching python..."
sleep 2
echo "entrypoint: starting python app"
exec python -u app.py
