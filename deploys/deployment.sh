DEFAULT_DB_NAME=$1
ADMIN_USER=admin
ADMIN_PASS=admin
CV_DIR=$(pwd)

if [ -z ${DEFAULT_DB_NAME} ];
then
    echo "Usage: $0 <database name>"
    exit 1
fi

echo "Create ${DEFAULT_DB_NAME} data base"
sudo sed -i '/^local/c\local all all trust' /etc/postgresql/*/main/pg_hba.conf
sudo service postgresql restart
dropdb -U postgres ${DEFAULT_DB_NAME}
createdb -U postgres -T template0 -E utf8 -O postgres ${DEFAULT_DB_NAME}

echo "Set up CV web-interface"
echo $'{\n\t\"ENGINE\": \"django.db.backends.postgresql_psycopg2\",\n\t\"NAME\": \"'${DEFAULT_DB_NAME}$'\",\n\t\"USER\": \"postgres\"\n}' > ${CV_DIR}/bridge/bridge/db.json
echo -e 'from bridge.development import *\nPERFORM_AUTO_SAVE=False' > ${CV_DIR}/bridge/bridge/settings.py
python3 ${CV_DIR}/bridge/manage.py compilemessages
python3 ${CV_DIR}/bridge/manage.py makemigrations
python3 ${CV_DIR}/bridge/manage.py migrate
echo "from django.contrib.auth import get_user_model; User = get_user_model(); User.objects.create_superuser('${ADMIN_USER}', '', '${ADMIN_PASS}')" | python3 ${CV_DIR}/bridge/manage.py shell
echo "from django.contrib.auth.models import User; from bridge.populate import Population, extend_user; user = User.objects.first(); extend_user(user, 2); Population(user=user)" | python3 ${CV_DIR}/bridge/manage.py shell

echo "Launch web-interface by command: './start.sh --host <host> --port <port> &'"

