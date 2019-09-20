#!/bin/bash
#
# Klever-CV is a web-interface for continuous verification results visualization.
#
# Copyright (c) 2018-2019 ISP RAS (http://www.ispras.ru)
# Ivannikov Institute for System Programming of the Russian Academy of Sciences
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

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

