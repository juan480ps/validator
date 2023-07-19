import sys, yaml

print(sys.argv)

try:
    db = sys.argv[4]#1
except Exception as e:
    db = sys.argv[1]#1

file = open('/opt/flask/validator/config/db/db_config_pstgr.yaml', 'r')
data = yaml.safe_load(file)
file.close()

postgresql = data

postgresqlConfig = "postgresql://{}:{}@{}/{}".format(postgresql['user'], postgresql['passwd'], postgresql['host'], db)