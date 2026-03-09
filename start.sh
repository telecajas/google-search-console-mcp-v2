#!/bin/sh
exec gunicorn gsc_server_remote:app -w 2 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:${PORT:-8000}
