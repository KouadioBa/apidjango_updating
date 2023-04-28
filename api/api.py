from ninja import NinjaAPI
from ninja import Router as apiRouter
from django.http import HttpResponse
from api.schema import (notFoundSchema, userRegister,
                        responseStdr, userLoginPassword, userLight,singleInfo)
from ninja.errors import HttpError
from ninja.errors import ValidationError
from rest_framework import status
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate

api = NinjaAPI()
core = apiRouter()


@api.exception_handler(ValidationError)
def custom_validation_errors(request, exc):
    print(exc.errors)  # <--------------------- !!!!
    return api.create_response(request,
                               {"status": 422,
                                "isError": "True",
                                "data": exc.errors,
                                "msg": "erreur",
                                "method": "POST"}, status=422)


def searchUsername(userstring):
    try:
        uid = get_user_model().objects.get(username=userstring)
        print(uid)
        return uid
    except:
        return None


def searchUserEmail(email):
    try:
        uid = get_user_model().objects.get(email=email)
        return uid
    except:
        return None

def searchUserPhoneNumber(phone):
    try:
        uid = get_user_model().objects.get(phone_number=phone)
        return uid
    except:
        return None

@core.post("/checkUserName", response={200: responseStdr, 404: responseStdr, 422: responseStdr})
def checkUserName(request, user: singleInfo):
    try:
        usernameExist = searchUsername(user.username)

        if usernameExist == None :
            return 200, {"status": 200,
                         "isError": "True",
                         "data": "",
                         "msg": "notExisting",
                         "userid": "",
                         "method": "POST"}
        else:
            if usernameExist != None:
                return 200, {"status": 202,
                             "isError": "True",
                             "data": "",
                             "msg": "username déjà existant",
                             "userid": user.username,
                             "method": "POST"}
    except:
        return 404, {"status": 201,
                     "isError": "True",
                     "data": "erreur format",
                     "msg": "erreur dans le web service",
                     "method": "POST"}

@core.post("/loginUser", response={200: userLight, 201:responseStdr,  404: responseStdr, 422: responseStdr})
def loginUser(request, user: userLoginPassword):
    try:
        actualuser = authenticate(
            username=user.username, password=user.password)
        if actualuser is not None:
            finalUser = searchUsername(user.username)
            t, created = Token.objects.get_or_create(user=finalUser)
            print(t.key)
            # A backend authenticated the credentials
            #token = Token.objects.create(actualuser)
            # print(token.key)
            return 200, {"status": 200,
                         "isError": "False",
                         "data": actualuser.get_username(),
                         "msg": "user authentifié avec succès",
                         "userid":  actualuser.pk,
                         "token":t.key,
                         "method": "POST"}
        else:
            return 201, {"status": 201,
                         "isError": "True",
                         "data": "",
                         "msg": "login/password Incorrect",
                         "userid":  user.username,
                         "method": "POST"}
    except:
        return 404, {"status": 201,
                     "isError": "True",
                     "data": "erreur format",
                     "msg": "erreur dans le web service",
                     "method": "POST"}

@core.post("/addUser", response={200: responseStdr, 404: responseStdr, 422: responseStdr})
def addUser(request, user: userRegister):
    try:
        usernameExist = searchUsername(user.username)
        emailExist = searchUserEmail(user.email)
        phoneNumber = searchUserPhoneNumber(user.phone_numberemail)

        if usernameExist == None and emailExist == None:
            newuser = get_user_model().objects.create(
                username=user.username,
                email=user.email,
                first_name=user.first_name,
                last_name=user.last_name,
                phone_number=user.phone_number
            )
            newuser.set_password(user.password)
            newuser.save()
            return 200, {"status": 200,
                         "isError": "True",
                         "data": user,
                         "msg": "user crée avec succès",
                         "userid": newuser.pk,
                         "method": "POST"}
        else:
            if usernameExist != None:
                return 200, {"status": 202,
                             "isError": "True",
                             "data": "",
                             "msg": "username déjà existant",
                             "userid": user.username,
                             "method": "POST"}

            if emailExist != None:
                return 200, {"status": 203,
                             "isError": "True",
                             "data": "",
                             "msg": "email déjà existant",
                             "userid": user.email,
                             "method": "POST"}
    except:
        return 404, {"status": 201,
                     "isError": "True",
                     "data": "erreur format",
                     "msg": "erreur dans le web service",
                     "method": "POST"}

@core.post("/addUser", response={200: responseStdr, 404: responseStdr, 422: responseStdr})
def addUser(request, user: userRegister):
    try:
        usernameExist = searchUsername(user.username)
        emailExist = searchUserEmail(user.email)
        phoneNumber = searchUserPhoneNumber(user.phone_numberemail)

        if usernameExist == None and emailExist == None:
            newuser = get_user_model().objects.create(
                username=user.username,
                email=user.email,
                first_name=user.first_name,
                last_name=user.last_name,
                phone_number=user.phone_number
            )
            newuser.set_password(user.password)
            newuser.save()
            return 200, {"status": 200,
                         "isError": "True",
                         "data": user,
                         "msg": "user crée avec succès",
                         "userid": newuser.pk,
                         "method": "POST"}
        else:
            if usernameExist != None:
                return 200, {"status": 202,
                             "isError": "True",
                             "data": "",
                             "msg": "username déjà existant",
                             "userid": user.username,
                             "method": "POST"}

            if emailExist != None:
                return 200, {"status": 203,
                             "isError": "True",
                             "data": "",
                             "msg": "email déjà existant",
                             "userid": user.email,
                             "method": "POST"}
    except:
        return 404, {"status": 201,
                     "isError": "True",
                     "data": "erreur format",
                     "msg": "erreur dans le web service",
                     "method": "POST"}

@core.get("/modUser/{idUser}", response={404: notFoundSchema})
def modUser(request, idUser: int):
    try:
        a = idUser + "1"
        return HttpResponse("Hello world!")
    except idUser:
        return 404, {"message": "ERREUR SUR LE SCHEMA : "+str(idUser)}

