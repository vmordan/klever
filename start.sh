#!/bin/bash
DEFAULT_HOST=localhost
DEFAULT_PORT=8999
DEFAULT_DEPLOYMENT_DIR=deploys
DEFAULT_PID_FILE=${DEFAULT_DEPLOYMENT_DIR}/current.pid
DEFAULT_LOG_FILE=${DEFAULT_DEPLOYMENT_DIR}/current.log
CV_DIR=$(pwd)

host=${DEFAULT_HOST}
port=${DEFAULT_PORT}
log=${DEFAULT_LOG_FILE}

usage()
{
    echo "Usage: $0 [--host host] [--port port] [--log log-file]"
    echo -e "\t--host change host name (default is ${DEFAULT_HOST})"
    echo -e "\t--port change port number (default is ${DEFAULT_PORT})"
    echo -e "\t--log change server log file (default is ${DEFAULT_LOG_FILE})"
    exit 1
}

while [[ "$1" != "" ]]; do
    case $1 in
        --host )        shift; host="$1" ;;
        --port )        shift; port="$1" ;;
        --log )         shift; log="$1" ;;
        -h | --help )   usage ;;
        * )             usage ;;
    esac
    shift
done

if [ -z "${log}" ]; then
    log=${DEFAULT_LOG_FILE}
fi

echo $$ > ${DEFAULT_PID_FILE}

echo "Starting CV web-interface on ${host}:${port}"
nohup python3 ${CV_DIR}/bridge/manage.py runserver ${host}:${port} &> ${DEFAULT_LOG_FILE}

