import jwt
import secrets

from fastapi import Depends, status, HTTPException, Request, Response, APIRouter
from fastapi_jwt_auth import AuthJWT

from helper.authentication import *
from helper.config import config, TOKEN_EXCEPTION, AUTH_EXCEPTION
from models.auth import *
from worker import send_email_task


auth_router = APIRouter(
    prefix="/auth",
    tags=['auth']
)

@auth_router.post('/register', status_code=status.HTTP_201_CREATED)
async def register(data: userRegister_pydantic, request: Request):
    user_info = data.dict(exclude_unset=True)
    redis_conn.setex("user:create_request", 15*60, json.dumps(user_info))
    user_info['password'] = User.get_hashed_password(user_info['password'])
    user = await User.create(**user_info)

    redis_conn.setex("user:create", 15*60, f"{user.name} has been created")

    d = {"id": user.id}
    token = jwt.encode(d, config['SECRET_KEY'], algorithm="HS256").decode()
    domain = request.client.host
    link = f"http://{domain}:8000/auth/email-verify/?token={token}"
    redis_conn.setex("user:link", 15*60, f"{link}")
    body = f"""
        Hi {user.name}, 
        Please use the link below to verify your account {link}
    """
    data = {
        "subject": "Verify your account",
        "body": body,
        "to": [user.email]
    }
    send_email_task.delay(data)
    return {"message": "We've sent you an email to verify your account"}


@auth_router.get('/email-verify', status_code=status.HTTP_200_OK)
async def email_verify(token: str):
    try:
        payload = jwt.decode(token, config['SECRET_KEY'], algorithms="HS256")
        user = await User.get(id=payload['id'])
        if user and not user.is_verified:
            user.is_verified = True
            await user.save()
            
            return {"message": "Successfully activated"}
    except jwt.exceptions.DecodeError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token is invalid, please request a new one", headers={"WWW-Authenticate": "Bearer"})
    except jwt.exceptions.ExpiredSignatureError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token is expired, please request a new one", headers={"WWW-Authenticate": "Bearer"})


@auth_router.post('/login', status_code=status.HTTP_200_OK)
async def login(data: userLogin_pydantic, Authorize: AuthJWT=Depends()):
    user_info = data.dict()
    user = await User.get(email=user_info['email'])

    if user and user.verify_password(user_info['password']):
        access_token = Authorize.create_access_token(subject=user.email, user_claims={"is_staff": user.is_staff})
        refresh_token = Authorize.create_refresh_token(subject=user.email)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token
        }

    raise AUTH_EXCEPTION


@auth_router.post('/reset-password', status_code=status.HTTP_201_CREATED)
async def reset_password(data: userResetPassword_pydantic, request: Request):
    user = await User.get(email=data.dict()['email'])

    if user:
        d = {"id": user.id, "name": user.name}
        token = secrets.token_hex()
        uidb64 = create_signed_token(token.encode('utf-8'), d)
        domain = request.client.host
        link = f"http://{domain}:8000/auth/reset-password-confirm/{uidb64}/{token}/"
        body = f"""
            Hi {user.name},
            Please use the link below to reset your password {link}
        """
        data = {
            "subject": "Reset your password",
            "body": body,
            "to": [user.email]
        }
        send_email_task.delay(data)

        return {"message": "We've sent you an email to reset your password"}
    raise AUTH_EXCEPTION


@auth_router.post('/reset-password-confirm/{uidb64}/{token}/')
async def reset_password_confirm(uidb64: str, token: str):
    (verified, payload) = verify_signed_token(token.encode('utf-8'), uidb64)

    if verified:
        return {"success": True, "uidb64": uidb64, "token": token}

    raise TOKEN_EXCEPTION


@auth_router.post('/set-new-password')
async def set_new_password(data: ResetPasswordReq):
    req = data.dict()
    (verified, payload) = verify_signed_token(req['token'].encode('utf-8'), req['uidb64'])
    if verified:
        user = await User.get(id=payload['id'])
        user.password = User.get_hashed_password(req['password'])
        await user.save()

        return {"message": "Changed password successfully"}

    raise TOKEN_EXCEPTION


@auth_router.post('/logout')
@validate_token
async def logout(Authorize: AuthJWT=Depends()):
    jti = Authorize.get_raw_jwt()['jti']
    redis_conn.setex(jti, settings.access_expires, "true")
    return Response(status_code=status.HTTP_204_NO_CONTENT)

