DEFAULT_DEPLOYMENT_DIR=deploys
DEFAULT_PID_FILE=${DEFAULT_DEPLOYMENT_DIR}/current.pid
if [ ! -f "${DEFAULT_PID_FILE}" ]; then
    echo "There is no server process"
    exit 1
fi
PID=$(cat ${DEFAULT_PID_FILE})

rm ${DEFAULT_PID_FILE}

pkill -P $PID
kill -9 -$PID

