import redis

from fastapi import Depends, FastAPI
from fastapi_jwt_auth import AuthJWT
from tortoise.contrib.fastapi import register_tortoise

from routers.auth_router import auth_router
from helper.config import config
from helper.authentication import validate_token



app = FastAPI()

app.include_router(auth_router)
register_tortoise(
    app,
    db_url=config['DATABASE_URL'],
    modules={"models": ["models.auth"]},
    generate_schemas=True,
    add_exception_handlers=True
)

@app.get('/')
@validate_token
def index(Authorize: AuthJWT=Depends()):
    return {"message": "Hello World"}


@app.get('/logs')
def get_log():
    r = redis.StrictRedis(host="redis-12656.c54.ap-northeast-1-2.ec2.cloud.redislabs.com", port=12656, password="0VmDJVRtUQ3IG5J0AzYJYqbyXTVWi6AB", db=0, decode_responses=True)

    keys = [key for key in r.scan_iter('user:*')]
    data = r.mget(keys)
    return data