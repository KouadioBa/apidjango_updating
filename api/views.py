import json
import pandas as pd
import datetime,pytz
import random, string, os,json
from django.db.models import Sum
from django.utils import timezone
from django.db.models import Count
from datetime import datetime, timedelta
from django.db.models import Prefetch
from django.utils.decorators import method_decorator
from django.http import Http404,HttpResponse,JsonResponse
from .authentication import ExpiringTokenAuthentication

from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from django.shortcuts import get_object_or_404
from django.contrib.auth import authenticate,logout

from .serializers import CountrySerializer,AnswersSectionSerializer,EducationSerializer,UserSerializer,TypeIDSerializer,MediaSerializer,ClientsSerializer,DashboardsSerializer,FootsoldiersSerializer,PrivilegeSerializer
from .serializers import SectionsSerializer,PosSerializer,ProduitSerializer,ExamSerializer,UserExamenSerializer,AnswersExamen,UploadSerializer,TrainingSerializer,UserScoreExamSerializer,LocalitySerializer,UserExamSerializer
from .serializers import TypeIDSerializer ,UsersClientSerializer,TargetSerializer,ChaptersSerializer,QuizSectionSerializer,QuizExamen,QuizExamenSerializer,AnswersExamenSerializer,IndustrySerializer,KycSerializer

from .models import EducationLevel,Locality,User,Countries,TokenPin,TypeID,Media,Kyc,Clients,Dashboards,Industry,Produit,Training,AnswersSection,UserScoreExam,Chapters,Exam
from .models import Kyc, User, EducationLevel, Locality, Countries, TypeID, Media,Footsoldiers,Pos,Domaine,UsersClient,Target,Sections,QuizSection,Privilege,UserExam,TypeID

from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework import viewsets,status,generics
from django_filters import rest_framework as filters
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.authtoken.views import ObtainAuthToken
from django.http import HttpResponseBadRequest
from rest_framework.decorators import authentication_classes, permission_classes,api_view
from rest_framework.parsers import MultiPartParser, FormParser,FileUploadParser


######################################### Login, token ##################################################
# connexion user
class CustomAuthToken(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)

        data = {}

        if not user:
            data['login_status'] = 'Echec'

        utc_now = datetime.utcnow()
        utc_now = utc_now.replace(tzinfo=pytz.utc)

        result = Token.objects.filter(user=user, created__lt=utc_now - timedelta(seconds=10)).delete()

        # Create a new token for the user
        token, created = Token.objects.get_or_create(user=user)

        # Set the expiration time for the token
        expiration_time = timezone.now() + timezone.timedelta(seconds=7200)
        token.expires = expiration_time
        token.save()

        if token.expires < timezone.now():
            data['token_status'] = 'Token invalid'

        user_serializer = UserSerializer(user)
        data = {
            'user': user_serializer.data,
            'token': token.key,
            'token_status': 'Token valid' if not created else 'New Token',
            'date_expiration': expiration_time,
            'login_status': 'Valid',
        }
        return Response(data=data)

# déconnexion super admin
class CustomLogout(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        if request.user.is_authenticated:
            token = Token.objects.get(user=request.user)
            token.delete()
            return Response({'message': 'You have been successfully logged out.'})
        else:
            return Response({'error': 'You must be logged in to logout.'})
        
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

######################################### CRUD for user ##################################################
# list of users
class ListUser(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        queryset = User.objects.all()
        data = {
            'Users': list(queryset.values())
        }
        return Response(data)
    
    serializer_class = UsersClientSerializer
    filter_backends = (filters.DjangoFilterBackend)

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# list user for client
class ClientUsersView(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    serializer_class = UserSerializer

    def get(self, request):
        user = request.user
        users = User.objects.filter(the_client=user.the_client)
        users_list = list(users.values())
        return JsonResponse(users_list, safe=False)
    filter_backends = (filters.DjangoFilterBackend)

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
# Afficher les détails d'un user
class DetailOneUser(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id, format=None):
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            data = {'error':"User dont exist"}
            return JsonResponse(data, status=404)
            
        data = {
            'user_id': user.id,
            'user_email': user.email,
            'user_identifiant': user.username,
            'privilege_id': user.privilege_id,
            'country_id': user.country_id,
            'client_id': user.the_client,
            'photo': user.profile_picture if user.profile_picture else None,
        }

        return JsonResponse(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
 
# create one user
class CreateOneUser(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def post(self, request, format=None):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid(raise_exception=False):
            user_data = serializer.validated_data
            user_obj = User.objects.create(
                email=user_data['email'],
                nom=user_data['nom'],
                prenoms=user_data['prenoms'],
                username=user_data['username'],
                password=user_data['password'],
                niveau_education=user_data['niveau_education'],
                country=user_data['country'],
                numero=user_data['numero'],
                date_naissance=user_data['date_naissance'],
                type_piece=user_data['type_piece'],
                numero_piece=user_data['numero_piece'],
                date_expiration=user_data['date_expiration'],
                piece_recto=user_data['piece_recto'],
                piece_verso=user_data['piece_verso'],
                profile_picture=user_data['profile_picture'],
                privilege=user_data['privilege'],
                the_client=user_data['the_client'],
            )
            data = {'message': 'User successfully added'}
            return JsonResponse(data)
        else:
            errors = serializer.errors
            new_error = {}
            for field_name, field_errors in errors.items():
                new_error[field_name] = field_errors[0]
            return Response(new_error, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request, format=None):
        return JsonResponse({'error': 'Unauthorized method'})
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
        
# update one user
class UpdateOneUser(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    parser_classes = (MultiPartParser, FormParser, FileUploadParser)
    serializer_class = UserSerializer
    lookup_field = 'id'
    queryset = User.objects.all()
    
            
    def get_object(self, user_id):
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise Http404
        
            
    def put(self, request, user_id):
        user = self.get_object(user_id)
        user.email = request.data.get('email', user.email)
        user.nom = request.data.get('nom', user.nom)
        user.prenoms = request.data.get('prenoms', user.prenoms)
        country_id = request.data.get('country')
        if country_id:
            countries = Countries.objects.get(id_country=country_id)
            user.country = countries
        user.username = request.data.get('username', user.username)
        user.password = request.data.get('password', user.password)
        user.profile_picture = request.data.get('profile_picture', user.profile_picture)
        client = request.data.get('the_client')
        if client:
            clients = Clients.objects.get(id_client=client)
            user.the_client = clients
        privileges = request.data.get('privilege')
        if privileges:
            privilegess = Privilege.objects.get(id=privileges)
            user.privilege = privilegess
        user.save()
        data = {'message': 'User changed successfully'}
        return JsonResponse(data)
    
    def get(self, request, format=None):
        return JsonResponse({'error': 'Unauthorized method'})
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
# delete one user
class DeleteOneUser(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def delete(self, request, user_id, format=None):
        user = get_object_or_404(User, id=user_id)
        user.delete()
        return Response({'message': 'User deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalide'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
######################################### CRUD Final exam section ##################################################
# userscore crud
class UserScoreCreate(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def post(self, request, format=None):
        id_exam = request.POST.get('id_exam', None)
        if not id_exam:
            return HttpResponse("Le champ id_exam est requis.")
        score = request.POST.get('score', None)
        if not score:
            return HttpResponse("Le champ score est requis.")
        nombredepoints = request.POST.get('nombredepoints', None)
        if not nombredepoints:
            return HttpResponse("Le champ nombredepoints est requis.")
        results = request.POST.get('results', None)
        if not results:
            return HttpResponse("Le champ results est requis.")

        try:
            examen = Exam.objects.get(id_examen=id_exam)
        except Exam.DoesNotExist:
            return HttpResponse("L'examen spécifié n'existe pas.")
        
        user = request.user
        if not user.is_superuser:
            try:
                privilege_admin = Privilege.objects.get(id=1)
            except Privilege.DoesNotExist:
                data = {'message':"Le privilège 'admin' n'existe pas."}
                return HttpResponse(data)

            if not user.privilege == privilege_admin:
                data = {'message':"Vous n'avez pas le droit de créer un utilisateur."}
                return HttpResponse(data)

        user_score_exam = UserScoreExam(
            id_exam=examen, 
            id_user=user,
            score=score,
            results=results,
            nombredepoints=nombredepoints,
        )
        user_score_exam.save()

        data = {'message': 'Le score du user ajouté avec succès'}
        return JsonResponse(data)
    
    def get(self, request, format=None):
        return JsonResponse({'error': 'Méthode non autorisée'})
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalide'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# userscore list
class UserScoreList(generics.ListAPIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        queryset = UserScoreExam.objects.filter(user = request.user)
        data = {
            'Scores des users': list(queryset.values())
        }
        return Response(data)
    serializer_class = UserScoreExamSerializer

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalide'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

######################################### CRUD Exam ##################################################
# add one quiz for exam
class AnswerExamCreate(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def post(self, request, format=None):
        serializer = AnswersExamenSerializer(data=request.data)
        if serializer.is_valid(raise_exception=False):
            answerexamen_data = serializer.validated_data
            answerexamen_obj = AnswersExamen.objects.create(
                id_quiz_examen = answerexamen_data['id_quiz_examen'],
                answer_label = answerexamen_data['answer_label'],
                answer_correct = answerexamen_data['answer_correct']
            )
            data = {'message': 'answer add successfully'}
            return JsonResponse(data)
        else:
            errors = serializer.errors
            new_error = {}
            for field_name, field_errors in errors.items():
                new_error[field_name] = field_errors[0]
            return Response(new_error, status=status.HTTP_400_BAD_REQUEST)
        
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# list of answerexam
class AnswerExamList(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        queryset = AnswersExamen.objects.all()
        data = {
            'Questions des examens': list(queryset.values())
        }
        return Response(data)
    serializer_class = AnswersExamenSerializer

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# add user for exam
class UserExamCreate(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def post(self, request, format=None):
        serializer = UserExamSerializer(data=request.data)
        if serializer.is_valid(raise_exception=False):
            exam_data = serializer.validated_data
            exam_obj = UserExam.objects.create(
                id_quiz = exam_data['id_quiz'],
                choice = exam_data['choice'],
                answer = exam_data['answer'],
                user = exam_data['user']
            )
            data = {'message': 'User added successfully'}
            return JsonResponse(data)
        else:
            errors = serializer.errors
            new_error = {}
            for field_name, field_errors in errors.items():
                new_error[field_name] = field_errors[0]
            return Response(new_error, status=status.HTTP_400_BAD_REQUEST)
        
    
    def get(self, request, format=None):
        return JsonResponse({'error': 'Méthode non autorisée'})
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalide'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# list of user 
class UserExamList(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        queryset = UserExam.objects.all()
        data = {
            'List des participants': list(queryset.values())
        }
        return Response(data)
    serializer_class = UserExamenSerializer

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalide'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

######################################### CRUD Exam ##################################################
# Add one exam
class ExamCreate(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def post(self, request, format=None):
        serializer = ExamSerializer(data=request.data)
        if serializer.is_valid(raise_exception=False):
            exam_data = serializer.validated_data
            exam_obj = Exam.objects.create(
                id_training = exam_data['id_training'],
                exam_name = exam_data['exam_name'],
                exam_description = exam_data['exam_description']
            )
            data = {'message': 'Exam quiz added successfully'}
            return JsonResponse(data)
        else:
            errors = serializer.errors
            new_error = {}
            for field_name, field_errors in errors.items():
                new_error[field_name] = field_errors[0]
            return Response(new_error, status=status.HTTP_400_BAD_REQUEST)
        
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# liste of examen
class ExamList(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        queryset = Exam.objects.all()
        data = {
            'Exam List': list(queryset.values())
        }
        return Response(data)
    serializer_class = ExamSerializer

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

######################################### CRUD Quiz_Exam ##################################################
# add one quiz for one exam
class AddOneQuizExam(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def post(self, request, format=None):
        serializer = QuizExamenSerializer(data=request.data)
        if serializer.is_valid(raise_exception=False):
            quizexamen_data = serializer.validated_data
            quizexamen_obj = QuizExamen.objects.create(
                id_examen = quizexamen_data['id_examen'],
                quiz_question_name = quizexamen_data['quiz_question_name'],
                quiz_question_points = quizexamen_data['quiz_question_points'],
                quiz_question_type = quizexamen_data['quiz_question_type'],
                quiz_question_media = quizexamen_data['quiz_question_media'],
                quiz_description = quizexamen_data['quiz_description']
            )
            data = {'message': 'Exam quiz added successfully'}
            return JsonResponse(data)
        else:
            errors = serializer.errors
            new_error = {}
            for field_name, field_errors in errors.items():
                new_error[field_name] = field_errors[0]
            return Response(new_error, status=status.HTTP_400_BAD_REQUEST)
        
        
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# list of quizExamen
class QuizExamList(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        queryset = Exam.objects.prefetch_related(
            Prefetch('quizexamen_set', queryset=QuizExamen.objects.prefetch_related('answersexamen_set'))
        )
        data = {
            'La liste des Examens avec le nombre de quiz questions et les questions avec les réponses': [
                {
                    'examen': exam.exam_name,
                    'nombre_questions': exam.quizexamen_set.count(),
                    'questions': [
                        {
                            'id': question.id_quiz_examen,
                            'question': question.quiz_question_name,
                            'points': question.quiz_question_points,
                            'type': question.quiz_question_type,
                            'media': question.quiz_question_media.url,
                            'description': question.quiz_description,
                            'reponses': [
                                {
                                    'label': answer.answer_label,
                                    'correct': answer.answer_correct
                                } for answer in question.answersexamen_set.all()
                            ]
                        } for question in exam.quizexamen_set.all()
                    ]
                } for exam in queryset
            ]
        }
        return Response(data)

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalide'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# update one quizexam
class UpadateOneQuizExam(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self, quiz_id):
        try:
            return QuizExamen.objects.get(id_quiz_examen=quiz_id)
        except QuizExamen.DoesNotExist:
            raise Http404

    def put(self, request, quiz_id):
        quiz = self.get_object(quiz_id)
        quiz.quiz_question_name = request.data.get('quiz_question_name', quiz.quiz_question_name)
        quiz.quiz_question_points = request.data.get('quiz_question_points', quiz.quiz_question_points)
        quiz.quiz_question_type = request.data.get('quiz_question_type', quiz.quiz_question_type)
        quiz.quiz_question_media = request.data.get('quiz_question_media', quiz.quiz_question_media)
        quiz.quiz_description = request.data.get('quiz_description', quiz.quiz_description)
        quiz.save()
        exam_quiz_serializer = QuizExamenSerializer(quiz)
        data = {
            'Quiz_Examen': exam_quiz_serializer.data,
            'message': 'Le quiz and reponse changed seuccessfully'
        }
        return Response(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# delete one training
class DeleteOneQuizExam(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def delete(self, request, quiz_id):
        quiz_exam = get_object_or_404(QuizExamen, id_quiz_examen=quiz_id)
        quiz_exam.delete()
        data = {'message': 'Quiz Exam of section deleted successfully.'}
        return JsonResponse(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

######################################### CRUD answers section ##################################################
# add one answer section
class AddOneAnswerSection(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def post(self, request, format=None):
        serializer = AnswersSectionSerializer(data=request.data)
        if serializer.is_valid(raise_exception=False):
            answersection_data = serializer.validated_data
            answersection_obj = AnswersSection.objects.create(
                id_quiz = answersection_data['id_quiz'],
                answer_correct = answersection_data['answer_correct'],
                answer_label = answersection_data['answer_label'],
            )
            data = {'message': 'Answer quiz added sucessfully'}
            return JsonResponse(data)
        else:
            errors = serializer.errors
            new_error = {}
            for field_name, field_errors in errors.items():
                new_error[field_name] = field_errors[0]
            return Response(new_error, status=status.HTTP_400_BAD_REQUEST)
        
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# list of quiz section
class ListAnswerSection(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        queryset = AnswersSection.objects.all()
        data = {
            'Answer for Section': list(queryset.values())
        }
        return Response(data)
    serializer_class = SectionsSerializer

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

######################################### CRUD quiz section ##################################################
# add one quiz for section
class AddOneQuizSection(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def post(self, request, format=None):
        serializer = QuizSectionSerializer(data=request.data)
        if serializer.is_valid(raise_exception=False):
            quizsection_data = serializer.validated_data
            quizsection_obj = QuizSection.objects.create(
                id_section = quizsection_data['id_section'],
                quiz_question_name = quizsection_data['quiz_question_name'],
                quiz_question_points = quizsection_data['quiz_question_points'],
                quiz_question_type = quizsection_data['quiz_question_type'],
                quiz_question_media = quizsection_data['quiz_question_media'],
                quiz_description = quizsection_data['quiz_description'],
            )
            data = {'message': 'Quiz added successfully'}
            return JsonResponse(data)
        else:
            errors = serializer.errors
            new_error = {}
            for field_name, field_errors in errors.items():
                new_error[field_name] = field_errors[0]
            return Response(new_error, status=status.HTTP_400_BAD_REQUEST)
        
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# update one quiz
class UpdateOneSectionQuiz(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self, quiz_section_id):
        try:
            return QuizSection.objects.get(id_quiz_section=quiz_section_id)
        except QuizSection.DoesNotExist:
            raise Http404

    def put(self, request, quiz_section_id):
        quiz_section = self.get_object(quiz_section_id)

        section_quiz = request.data.get('id_section')
        if section_quiz:
            sections = Sections.objects.get(id_section=section_quiz)
            quiz_section.id_section = sections
        quiz_section.quiz_question_name = request.data.get('quiz_question_name', quiz_section.quiz_question_name)
        quiz_section.quiz_question_points = request.data.get('quiz_question_points', quiz_section.quiz_question_points)
        quiz_section.quiz_question_type = request.data.get('quiz_question_type', quiz_section.quiz_question_type)
        quiz_section.quiz_question_media = request.data.get('quiz_question_media', quiz_section.quiz_question_media)
        quiz_section.quiz_description = request.data.get('quiz_description', quiz_section.quiz_description)
        quiz_section.save()

        quiz_section_serializer = QuizSectionSerializer(quiz_section)
        data = {
            'Quiz_for_section': quiz_section_serializer.data,
            'message': 'Quiz changed successfully'
        }
        return JsonResponse(data)

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
# list of quizs
class ListQuizSection(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]
    def get(self, request):
        sections = Sections.objects.all()
        data = []

        for section in sections:
            section_data = SectionsSerializer(section).data
            quiz_queryset = QuizSection.objects.filter(id_section=section.id_section)
            quiz_serializer = QuizSectionSerializer(quiz_queryset, many=True)
            section_data['quizzes'] = quiz_serializer.data
            data.append(section_data)
        return Response(data)

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# delete one training
class DeleteOneQuiz(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def delete(self, request, sectionquiz_id):
        quiz_section = get_object_or_404(QuizSection, id_quiz_section=sectionquiz_id)
        quiz_section.delete()
        data = {'message': 'Quiz of section deleted successfully.'}
        return JsonResponse(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

######################################### CRUD chapter ##################################################
# add one chapter
class AddOneChapter(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def post(self, request, format=None):
        serializer = ChaptersSerializer(data=request.data)
        if serializer.is_valid(raise_exception=False):
            chapter_data = serializer.validated_data
            chapter_obj = Chapters.objects.create(
                id_section = chapter_data['id_section'],
                chapter_name = chapter_data['chapter_name'],
                chapter_description = chapter_data['chapter_description'],
                chapter_order = chapter_data['chapter_order'],
                media = chapter_data['media'],
            )
            data = {'message': 'Chapter added successfully'}
            return JsonResponse(data)
        else:
            errors = serializer.errors
            new_error = {}
            for field_name, field_errors in errors.items():
                new_error[field_name] = field_errors[0]
            return Response(new_error, status=status.HTTP_400_BAD_REQUEST)
    
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# list of chapters
class ListChapter(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        queryset = Chapters.objects.all()
        data = {
            'Chapters': list(queryset.values())
        }
        return Response(data)
    serializer_class = ChaptersSerializer

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# update one chapter
class UpdateOneChapter(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self, chapter_id):
        try:
            return Chapters.objects.get(id_chapter=chapter_id)
        except Chapters.DoesNotExist:
            raise Http404

    def put(self, request, chapter_id):
        chapters = self.get_object(chapter_id)
        section = request.data.get('id_section')
        if section:
            sections = Sections.objects.get(id_section=section)
            chapters.id_section = sections
        chapters.chapter_name = request.data.get('chapter_name', chapters.chapter_name)
        chapters.chapter_description = request.data.get('chapter_description', chapters.chapter_description)
        chapters.save()

        chapter_serializer = ChaptersSerializer(chapters)
        data = {
        'chapters': chapter_serializer.data,
        'message': 'Chapter changed successfully'
        }
        return JsonResponse(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
# dlete one chapter
class DeleteOneChapter(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def delete(self, request, chapter_id):
        chapter = get_object_or_404(Chapters, id_chapter=chapter_id)
        chapter.delete()
        data = {'message': 'Chapter deleted successfully.'}
        return JsonResponse(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

######################################### CRUD section ##################################################
# add one section
class AddOneSection(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def post(self, request, format=None):
        serializer = SectionsSerializer(data=request.data)
        if serializer.is_valid(raise_exception=False):
            section_data = serializer.validated_data
            section_obj = Sections.objects.create(
                id_formation = section_data['id_formation'],
                sections_order = section_data['sections_order'],
                sections_name = section_data['sections_name'],
            )
            data = {'message': 'Section added successfully'}
            return JsonResponse(data)
        else:
            errors = serializer.errors
            new_error = {}
            for field_name, field_errors in errors.items():
                new_error[field_name] = field_errors[0]
            return Response(new_error, status=status.HTTP_400_BAD_REQUEST)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
# list of sections
class ListSection(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        sections = Sections.objects.all()
        data = []

        for section in sections:
            section_data = SectionsSerializer(section).data
            chapter_queryset = Chapters.objects.filter(id_section=section.id_section)
            chapter_serializer = ChaptersSerializer(chapter_queryset, many=True)
            section_data['chapters'] = chapter_serializer.data
            # quiz_queryset = QuizSection.objects.filter(id_section=section.id_section)
            # quiz_serializer = QuizSectionSerializer(quiz_queryset, many=True)
            # section_data['quizzes'] = quiz_serializer.data
            data.append(section_data)
        return Response(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# update one section
class UpdateOneSection(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self, section_id):
        try:
            return Sections.objects.get(id_section=section_id)
        except Sections.DoesNotExist:
            raise Http404

    def put(self, request, section_id):
        section = self.get_object(section_id)
        training = request.data.get('id_formation')
        if training:
            trainings = Training.objects.get(id_training=training)
            section.id_formation = trainings
        produit = request.data.get('sections_order')
        if produit:
            produits = Produit.objects.get(id_product=produit)
            section.sections_order = produits
        section.sections_name = request.data.get('sections_name', section.sections_name)
        section.save()

        section_serializer =  SectionsSerializer(section)
        data = {
            'Sections':section_serializer.data,
            'message': 'Training changed successfully'
        }
        return JsonResponse(data)


    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# delete one training
class DeleteOneSection(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def delete(self, request, section_id):
        section = get_object_or_404(Sections, id_section=section_id)
        section.delete()

        data = {'message': 'Section deleted successfully.'}
        return JsonResponse(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
######################################### CRUD training ##################################################
# liste des training
class ListTraining(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        queryset = Training.objects.all()
        data = {
            'Trainings': list(queryset.values()),
        }
        return Response(data)
    serializer_class = TrainingSerializer

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# list of trainings by client
class TrainingClientList(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = TrainingSerializer

    def get_queryset(self):
        # Récupérer le client associé à l'utilisateur connecté
        client = self.request.user.the_client
        # Récupérer les trainings associés à ce client
        queryset = Training.objects.filter(id_client=client)
        return queryset
    def get(self, request):
        queryset = self.get_queryset()
        serializer = self.serializer_class(queryset, many=True)
        return Response(serializer.data)
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
# add one training
class AddOneTraining(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def post(self, request, format=None):
        serializer = TrainingSerializer(data=request.data)
        if serializer.is_valid(raise_exception=False):
            training_data = serializer.validated_data
            training_obj = Training.objects.create(
                id_client = training_data['id_client'],
                countrie_id = training_data['countrie_id'],
                produit_id = training_data['produit_id'],
                training_name = training_data['training_name'],
                training_onBoarding = training_data['training_onBoarding'],
                training_min_score = training_data['training_min_score'],
                training_description = training_data['training_description'],
                training_mode = training_data['training_mode'],
                training_statut = training_data['training_statut'],
                training_category = training_data['training_category']
            )
            data = {'message': 'Training added successfully'}
            return JsonResponse(data)
        else:
            errors = serializer.errors
            new_error = {}
            for field_name, field_errors in errors.items():
                new_error[field_name] = field_errors[0]
            return Response(new_error, status=status.HTTP_400_BAD_REQUEST)
        
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
# delete one training
class DeleteOneTraining(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def delete(self, request, training_id):
        training = get_object_or_404(Training, id_training=training_id)
        training.delete()
        data = {'message': 'Training deleted successfully.'}
        return JsonResponse(data)

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# update one training
class UpdateOneTraining(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self, training_id):
        try:
            return Training.objects.get(id_training=training_id)
        except Training.DoesNotExist:
            raise Http404

    def put(self, request, training_id):
        training = self.get_object(training_id)
        country_id = request.data.get('countrie_id')
        if country_id:
            country = Countries.objects.get(id_country=country_id)
            training.countrie_id = country
        training.training_name = request.data.get('training_name', training.training_name)
        client_id = request.data.get('id_client')
        if client_id:
            client = Clients.objects.get(id_client=client_id)
            training.id_client = client
        produit = request.data.get('produit_id')
        if produit:
            produits = Produit.objects.get(id_product=produit)
            training.produit_id = produits
        training.training_onBoarding = request.data.get('training_onBoarding', training.training_onBoarding)
        training.training_min_score = request.data.get('training_min_score', training.training_min_score)
        training.training_description = request.data.get('training_description', training.training_description)
        training.training_mode = request.data.get('training_mode', training.training_mode)
        training.training_statut = request.data.get('training_statut', training.training_statut)
        training.training_category = request.data.get('training_category', training.training_category)
        training.save()

        training_serializer = TrainingSerializer(training)
        data = {
            'formations':training_serializer.data,
            'message': 'Training changed successfully'
        }
        return JsonResponse(data)

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

######################################## privilege CRUD ################################################
# add one privilege
class AddOnePrivilege(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def post(self, request, format=None):
        serializer = PrivilegeSerializer(data=request.data)
        if serializer.is_valid(raise_exception=False):
            privilege_data = serializer.validated_data
            country_obj = Privilege.objects.create(
                name = privilege_data['name'],
                description = privilege_data['description'],
            )
            data = {'message': 'Privilege successfully added'}
            return JsonResponse(data)
        else:
            errors = serializer.errors
            new_error = {}
            for field_name, field_errors in errors.items():
                new_error[field_name] = field_errors[0]
            return Response(new_error, status=status.HTTP_400_BAD_REQUEST)
        
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# list of privileges
class ListPrivilege(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        privilege = Privilege.objects.all()
        data = {
            'Privilèges': list(privilege.values()),
        }
        return Response(data)

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
      
######################################## typeID CRUD ################################################
# add one typeID
class AddOneTypeId(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def post(self, request, format=None):
        serializer = TypeIDSerializer(data=request.data)
        if serializer.is_valid(raise_exception=False):
            typeid_data = serializer.validated_data
            country_obj = TypeID.objects.create(
                id_name = typeid_data['id_name'],
                id_country = typeid_data['id_country'],
                number_typeid = typeid_data['number_typeid'],
            )
            data = {'message': 'TypeID successfully added'}
            return JsonResponse(data)
        else:
            errors = serializer.errors
            new_error = {}
            for field_name, field_errors in errors.items():
                new_error[field_name] = field_errors[0]
            return Response(new_error, status=status.HTTP_400_BAD_REQUEST)
        
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
# update one typeID
class UpdateOneTypeId(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self, type_id):
        try:
            return TypeID.objects.get(id_type=type_id)
        except TypeID.DoesNotExist:
            raise Http404
        
    def put(self, request, type_id):
        type = self.get_object(type_id)
        type.id_name = request.data.get('id_name', type.id_name)
        # récupérer l'objet Countries correspondant à partir de son ID et l'assigner au champ id_country
        country_id = request.data.get('id_country')
        if country_id:
            country = Countries.objects.get(id_country=country_id)
            type.id_country = country
        
        type.save()

        data = {'message': 'TypeID changed successfully'}
        return JsonResponse(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# delete one typeID
class DeleteOneTypeId(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def delete(self, request, type_id):
        typeid = get_object_or_404(TypeID, id_type=type_id)
        typeid.delete()
        data = {'message': 'TypeId deleted successfully.'}
        return JsonResponse(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
# list of typeID
class ListTypeId(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        counts_by_country = TypeID.objects.values('id_country__country_name').annotate(count=Count('id_country'))
        data = {}
        for count in counts_by_country:
            data[count['id_country__country_name']] = count['count']
        return Response(data)

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
      
######################################## education_level CRUD ################################################
# add one education_level
class AddOneEducationLevel(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def post(self, request, format=None):
        serializer = EducationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=False):
            level_data = serializer.validated_data
            level_obj = EducationLevel.objects.create(
                level_name=level_data['level_name'],
                id_country=level_data['id_country'],
                level_number=level_data['level_number'],
            )
            data = {'message': "Level Education successfully added"}
            return JsonResponse(data)
        else:
            errors = serializer.errors
            new_error = {}
            for field_name, field_errors in errors.items():
                new_error[field_name] = field_errors[0]
            return Response(new_error, status=status.HTTP_400_BAD_REQUEST)
        
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
# update one education_level
class UpdateOneEducationLevel(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self, education_id):
        try:
            return EducationLevel.objects.get(id_education=education_id)
        except EducationLevel.DoesNotExist:
            raise Http404

    def put(self, request, education_id):
        education = self.get_object(education_id)
        education.level_name = request.data.get('level_name', education.level_name)
        # récupérer l'objet Countries correspondant à partir de son ID et l'assigner au champ id_country
        country_id = request.data.get('id_country')
        if country_id:
            country = Countries.objects.get(id_country=country_id)
            education.id_country = country
        education.save()

        data = {'message': 'Education Level changed successfully'}
        return JsonResponse(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# delete one education_level
class DeleteOneEducationLevel(APIView):

    def delete(self, request, education_id, format=None):
        education = get_object_or_404(EducationLevel, id_education=education_id)
        education.delete()
        return Response({'message': 'Education Level deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
# list of level_education
class ListEducationLevel(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        counts_by_country = EducationLevel.objects.values('id_country__country_name').annotate(count=Count('id_country'))
        count_list = [count['count'] for count in counts_by_country]
        total_level = sum(count_list)
        data = {'Total_level': total_level}
        for count in counts_by_country:
            data[count['id_country__country_name']] = count['count']
        return Response(data)

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
      
######################################## countries CRUD ################################################
# Add one country
class AddOneCountries(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def post(self, request, format=None):
        country_name = request.data.get('country_name', None)
        if not country_name:
            data = {'message': 'country_name required'}
            return JsonResponse(data, status=400)
        country_prefixe = request.data.get('country_prefixe', None)
        if not country_prefixe:
            data = {'message': 'country_prefixe required'}
            return JsonResponse(data, status=400)
        flag = request.data.get('flag', None)
        if not flag:
            data = {'message': 'flag required'}
            return JsonResponse(data, status=400)
        
        countries = Countries(country_name=country_name,
                              country_prefixe=country_prefixe,
                              flag=flag)
        countries.save()

        # Mettre à jour le nombre de clients associés à ce pays
        num_clients = Clients.objects.filter(country_id=countries).count()
        countries.numbers_of_clients = num_clients
        countries.save()

        data = {'message': 'Countries ajouté avec succès',
                'number_of_clients': num_clients}
        return JsonResponse(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
# List of countries
class ListCountries(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        countries = Countries.objects.all()
        data = {
            'Pays': list(countries.values())
        }
        return Response(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
# update one country
class UpdateOneCountries(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self, country_id):
        try:
            return Countries.objects.get(id_country=country_id)
        except Countries.DoesNotExist:
            raise Http404

    def put(self, request, country_id):
        countries = self.get_object(country_id)
        countries.country_name = request.data.get('country_name', countries.country_name)
        countries.country_prefixe = request.data.get('country_prefixe', countries.country_prefixe)
        countries.flag = request.data.get('flag', countries.flag)
        countries.save()

        data = {'message': 'Country changed successfully'}
        return JsonResponse(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# delete one country
class DeleteOneCountries(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def delete(self, request, country_id, format=None):
        country = get_object_or_404(Countries, id_country=country_id)
        country.delete()
        return Response({'message': 'Country deleted successfully'}, status=status.HTTP_204_NO_CONTENT)

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

######################################## pos CRUD ################################################
# list of Pos
class ListPos(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):

        pos = Pos.objects.filter()
        # récupérer tous les objets Pos
        total_pos_active = pos.aggregate(Sum('pos_active'))['pos_active__sum']
        total_numb_pos = pos.aggregate(Sum('numb_pos'))['numb_pos__sum']
        total_pos_indication = pos.aggregate(Sum('pos_indication'))['pos_indication__sum']

        # sérialiser les objets Pos
        serializer = PosSerializer(pos, many=True)

        # renvoyer la réponse avec les objets sérialisés
        return Response({
        'Pos': serializer.data,
        'total_pos_active': total_pos_active,
        'total_numb_pos': total_numb_pos,
        'total_pos_indication': total_pos_indication
    })

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# pos for client
class ClientPosView(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        client_id = user.the_client.id_client
        pos = Pos.objects.filter(pos_client=client_id).values()
        pos_list = list(pos.values())
        # récupérer tous les objets Pos
        total_pos_active = pos.aggregate(Sum('pos_active'))['pos_active__sum']
        total_numb_pos = pos.aggregate(Sum('numb_pos'))['numb_pos__sum']
        total_pos_indication = pos.aggregate(Sum('pos_indication'))['pos_indication__sum']

        return Response({
        'Pos': pos_list,
        'total_pos_active': total_pos_active,
        'total_numb_pos': total_numb_pos,
        'total_pos_indication': total_pos_indication
    })
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# add one POS
class AddOnePos(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        file = request.FILES.get('file')
        pos_countrie = request.data.get('pos_countrie')
        pos_client = request.data.get('pos_client')

        if not file and (not pos_countrie or not pos_client):
            return Response({'error': 'File not found'})

        try:
            sheet_name = 'Sheet'
            if file:
                # sheet_name = file.name 
                df = pd.read_excel(file)
            else:
                df = pd.DataFrame(request.data)

            for index, row in df.iterrows():
                pos_name = row['pos_name'].strip().lower()
                pos_long = row['pos_long']
                pos_lat = row['pos_lat']

                pos_exists = Pos.objects.filter(pos_countrie_id=pos_countrie,
                                                pos_client_id=pos_client,
                                                pos_name=pos_name,
                                                pos_long=pos_long,
                                                pos_lat=pos_lat).exists()
                if not pos_exists:
                    pos = Pos(
                        pos_countrie_id=pos_countrie,
                        pos_client_id=pos_client,
                        pos_name=pos_name,
                        pos_long=pos_long,
                        pos_lat=pos_lat,
                        pos_active=row['pos_active'],
                        numb_pos=row['numb_pos'],
                        pos_indication=row['pos_indication']
                    )
                    pos.save()

            return Response({'success': f'Data imported has successfully from "{sheet_name}"'})
        except Exception as e:
            return Response({'error': str(e)})
        
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

######################################## target CRUD ################################################
# add one target
class AddOneTarget(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, format=None):
        file = request.FILES.get('file')
        target_countrie = request.data.get('target_countrie')
        target_client = request.data.get('target_client')

        if not file and (not target_countrie or not target_client):
            return Response({'error': 'File not found'})

        try:
            sheet_name = 'Sheet'
            if file:
                # sheet_name = file.name 
                df = pd.read_excel(file)
            else:
                df = pd.DataFrame(request.data)

            for index, row in df.iterrows():
                target_zone = row['target_zone'].strip().lower()
                target_month = row['target_month']

                target_exists = Target.objects.filter(target_countrie_id=target_countrie,
                                                       target_client_id=target_client,
                                                       target_zone=target_zone,
                                                       target_month=target_month).exists()
                if not target_exists:
                    target = Target(
                        target_countrie_id=target_countrie,
                        target_client_id=target_client,
                        target_zone=target_zone,
                        target_month=target_month,
                        target_moderm=row['target_moderm'],
                        target_routeurs=row['target_routeurs'],
                        target_airtelmoney=row['target_airtelmoney']
                    )
                    target.save()

            return Response({'success': f'Data imported has successfully from "{sheet_name}"'})
        except Exception as e:
            return Response({'error': str(e)})
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# list of targets
class TargetList(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        targets = Target.objects.all()
        # récupérer tous les objets Targets
        total_target_moderm = targets.aggregate(Sum('target_moderm'))['target_moderm__sum']
        total_target_routeurs = targets.aggregate(Sum('target_routeurs'))['target_routeurs__sum']
        total_target_airtelmoney = targets.aggregate(Sum('target_airtelmoney'))['target_airtelmoney__sum']

        serializer = TargetSerializer(targets, many=True)

        return Response({
        'targets': serializer.data,
        'total_target_moderm': total_target_moderm,
        'total_target_routeurs': total_target_routeurs,
        'total_target_airtelmoney': total_target_airtelmoney
        })

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# target for client view
class ClientTargetsView(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    serializer_class = TargetSerializer

    def get(self, request):
        user = request.user
        targets = Target.objects.filter(target_client=user.the_client)
        targets_list = list(targets.values())
        # récupérer tous les objets Targets
        total_target_moderm = targets.aggregate(Sum('target_moderm'))['target_moderm__sum']
        total_target_routeurs = targets.aggregate(Sum('target_routeurs'))['target_routeurs__sum']
        total_target_airtelmoney = targets.aggregate(Sum('target_airtelmoney'))['target_airtelmoney__sum']

        return Response({
        'targets': targets_list,
        'total_target_moderm': total_target_moderm,
        'total_target_routeurs': total_target_routeurs,
        'total_target_airtelmoney': total_target_airtelmoney
        })

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# update one target
class UpdateOneTarget(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def put(self, request, target_id):
        try:
            target = Target.objects.get(id_target=target_id)
        except Target.DoesNotExist:
            return Response({'error': 'Target does not exist'}, status=status.HTTP_404_NOT_FOUND)

        client = request.data.get('target_client')
        if client:
            clients = Clients.objects.get(id_client=client)
            target.target_client = clients
        target_contry = request.data.get('target_countrie')
        if target_contry:
            countris = Countries.objects.get(id_country=target_contry)
            target.target_countrie = countris
        target.target_zone = request.data.get('target_zone', target.target_zone)
        target.target_month = request.data.get('target_month', target.target_month)
        target.target_moderm = request.data.get('target_moderm', target.target_moderm)
        target.target_routeurs = request.data.get('target_routeurs', target.target_routeurs)
        target.target_airtelmoney = request.data.get('target_airtelmoney', target.target_airtelmoney)
        target.save()
        data = {'message': 'Target changed successfully'}
        return JsonResponse(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# delete one target
class DeleteOneTarget(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def delete(self, request, target_id, format=None):
        target = get_object_or_404(Target, id_target=target_id)
        target.delete()
        return Response({'message': 'Target deleted successfully'}, status=status.HTTP_204_NO_CONTENT)

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
######################################## KYC CRUD ###################################################
# Ajouter un nouveau KYC
class AddOneKYC(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = KycSerializer(data=request.data)
        if serializer.is_valid(raise_exception=False):
            kyc_data = serializer.validated_data
            kyc_obj = Kyc.objects.create(
                email = kyc_data['email'],
                nom = kyc_data['nom'],
                prenoms = kyc_data['prenoms'],
                niveau_education = kyc_data['niveau_education'],
                localite = kyc_data['localite'],
                pays = kyc_data['pays'],
                username = kyc_data['username'],
                date_naissance = kyc_data['date_naissance'],
                lieu_naissance = kyc_data['lieu_naissance'],
                type_piece = kyc_data['type_piece'],
                numero_piece = kyc_data['numero_piece'],
                date_expiration = kyc_data['date_expiration'],
                photo_selfie = kyc_data['photo_selfie'],
                piece_recto = kyc_data['piece_recto'],
                piece_verso = kyc_data['piece_verso'],
                isNomOk=False,
                isPrenomOk=False,
                isTypepPieceOk=False,
                isDateNaissanceOk=False,
                isLieuNaissanceOk=False,
                isTypePieceOk=False,
                isNumeroPieceOk=False,
                isDateExpirationOk=False,
                isPhotoSelfieOk=False,
                isPieceRectoOk=False,
                isPieceVersoOk=False,
                isAllok=False,
            )
            data = {'message': 'Kyc successfully added'}
            return JsonResponse(data)
        else:
            errors = serializer.errors
            new_error = {}
            for field_name, field_errors in errors.items():
                new_error[field_name] = field_errors[0]
            return Response(new_error, status=status.HTTP_400_BAD_REQUEST)
        
    def get(self, request, format=None):
        return JsonResponse({'error': 'Unauthorized method'})

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# List of KYC
class ListKYC(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):        

        kycs = Kyc.objects.all()
        data = {'Kyc': list(kycs.values())}
        return Response(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
# Mettre à jour un kyc existant
class UpdateOneKYC(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self, kyc_id):
        try:
            return Kyc.objects.get(id=kyc_id)
        except Kyc.DoesNotExist:
            raise Http404
    
    def put(self, request, kyc_id):
        kycs = self.get_object(kyc_id)
        kycs.email = request.data.get('email', kycs.email)
        kycs.nom = request.data.get('nom', kycs.nom)
        kycs.prenoms = request.data.get('prenoms', kycs.prenoms)
        kycs.username = request.data.get('username', kycs.username)
        kycs.date_naissance = request.data.get('date_naissance', kycs.date_naissance)
        kycs.lieu_naissance = request.data.get('lieu_naissance', kycs.lieu_naissance)
        kycs.numero_piece = request.data.get('numero_piece', kycs.numero_piece)
        kycs.date_expiration = request.data.get('date_expiration', kycs.date_expiration)
        kycs.photo_selfie = request.data.get('photo_selfie', kycs.photo_selfie)
        kycs.piece_recto = request.data.get('piece_recto', kycs.piece_recto)
        kycs.piece_verso = request.data.get('piece_verso', kycs.piece_verso)
        client = request.data.get('clients_kyc')
        if client:
            clients = Clients.objects.get(id_client=client)
            kycs.clients_kyc = clients
        kyc_contry = request.data.get('pays')
        if kyc_contry:
            countris = Countries.objects.get(id_country=kyc_contry)
            kycs.pays = countris
        kyc_type_piece = request.data.get('type_piece')
        if kyc_type_piece:
            type = TypeID.objects.get(id_type=kyc_type_piece)
            kycs.type_piece = type
        kyc_localite = request.data.get('localite')
        if kyc_localite:
            local = Locality.objects.get(id_locality=kyc_localite)
            kycs.localite = local
        kyc_education = request.data.get('niveau_education')
        if kyc_education:
            education = EducationLevel.objects.get(id_education=kyc_education)
            kycs.niveau_education = education
        kycs.save()

        data = {'message': 'Kyc changed successfully'}
        return JsonResponse(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# Supprimer un produit existant
class DeleteOneKyc(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def delete(self, request, kyc_id, format=None):
        kycs = get_object_or_404(Kyc, id=kyc_id)
        kycs.delete()
        return Response({'message': 'Kyc deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
    
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
######################################## FootSoldiers CRUD ################################################
# List of footsoldiers
class ListFootsoldier(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        footsoldiers = Footsoldiers.objects.all()
        data = {'Footsoldiers': list(footsoldiers.values())}
        return Response(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# footsoldiers for client
class FootsoldierListByClient(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    serializer_class = FootsoldiersSerializer

    def get(self, request):
        user = request.user
        footsoldiers = Footsoldiers.objects.filter(footsoldiers_clients=user.the_client)
        serializer = self.serializer_class(footsoldiers, many=True)
        return Response(serializer.data)

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
# Add one footsoldier
class AddOneFootsoldier(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def post(self, request): 
        serializer = FootsoldiersSerializer(data=request.data)
        if serializer.is_valid(raise_exception=False):
            footsoldier_data = serializer.validated_data
            footsoldier_obj = Footsoldiers.objects.create(
                footsoldiers_phonenumber = footsoldier_data['footsoldiers_phonenumber'],
                footsoldiers_fullname = footsoldier_data['footsoldiers_fullname'],
                footsoldiers_zone = footsoldier_data['footsoldiers_zone'],
                footsoldiers_clients = footsoldier_data['footsoldiers_clients'],
                footsoldiers_country = footsoldier_data['footsoldiers_country'],
                footsoldiers_picture = footsoldier_data['footsoldiers_picture'],
            )
            data = {'message': 'Footsoldiers successfully added'}
            return JsonResponse(data)
        else:
            errors = serializer.errors
            new_error = {}
            for field_name, field_errors in errors.items():
                new_error[field_name] = field_errors[0]
            return Response(new_error, status=status.HTTP_400_BAD_REQUEST)
        
    def get(self, request, format=None):
        return JsonResponse({'error': 'Unauthorized method'})
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
# Mettre à jour un footsoldiers existant
class UpdateOneFootsoldier(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self, footsoldiers_id):
        try:
            return Footsoldiers.objects.get(id_footsoldiers=footsoldiers_id)
        except Footsoldiers.DoesNotExist:
            raise Http404
        
    def put(self, request, footsoldiers_id):
        footsoldiers = self.get_object(footsoldiers_id)
        footsoldiers.footsoldiers_phonenumber = request.data.get('footsoldiers_phonenumber', footsoldiers.footsoldiers_phonenumber)
        footsoldiers.footsoldiers_fullname = request.data.get('footsoldiers_fullname', footsoldiers.footsoldiers_fullname)
        footsoldiers.footsoldiers_zone = request.data.get('footsoldiers_zone', footsoldiers.footsoldiers_zone)
        footsoldiers.footsoldiers_picture = request.data.get('footsoldiers_picture', footsoldiers.footsoldiers_picture)
        footsoldiers_clients = request.data.get('footsoldiers_clients')
        if footsoldiers_clients:
            clients = Clients.objects.get(id_client=footsoldiers_clients)
            footsoldiers.footsoldiers_clients = clients
        footsoldiers_country = request.data.get('footsoldiers_country')
        if footsoldiers_country:
            countri = Countries.objects.get(id_country=footsoldiers_country)
            footsoldiers.footsoldiers_country = countri
        footsoldiers.save()

        data = {'message': 'Footsoldier changed successfully'}
        return JsonResponse(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# Supprimer un produit existant
class DeleteOneFootsoldier(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def delete(self, request, footsoldiers_id, format=None):
        footsoldier = get_object_or_404(Footsoldiers, id_footsoldiers=footsoldiers_id)
        footsoldier.delete()
        return Response({'message': 'Footsoldiers deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
    
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalide'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

######################################## Clients CRUD #################################################
# list of clients
class ListClient(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        clients = Clients.objects.all()
        data = {'Clients': list(clients.values())}
        return Response(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# Add one client
class AddOneClient(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def post(self, request, format=None):
        serializer = ClientsSerializer(data=request.data)
        if serializer.is_valid(raise_exception=False):
            client_data = serializer.validated_data
            client_obj = Clients.objects.create(
                country_id = client_data['country_id'],
                client_logo = client_data['client_logo'],
                client_industry = client_data['client_industry'],
                client_name = client_data['client_name'],
                client_status = client_data['client_status'],
            )
            data = {'message': 'CLient successfully added'}
            return JsonResponse(data)
        else:
            errors = serializer.errors
            new_error = {}
            for field_name, field_errors in errors.items():
                new_error[field_name] = field_errors[0]
            return Response(new_error, status=status.HTTP_400_BAD_REQUEST)

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalide'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# Detail for one client
class DetailOneClient(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, client_id, format=None):
        try:
            clients = Clients.objects.get(id_client=client_id)
        except Clients.DoesNotExist:
            data = {'message':"This Client does not exist"}
            return JsonResponse(data, status=404)
            
        data = {
            'client_name': clients.client_name,
            'client_status': clients.client_status,
            'country_id': clients.country_id.id_country,
            'client_logo': request.build_absolute_uri(clients.client_logo.url),
            'client_industry': clients.client_industry.id_industry,
        }

        return Response(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
# Update one client
class UpdateOneClient(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self, client_id):
        try:
            return Clients.objects.get(id_client=client_id)
        except Clients.DoesNotExist:
            raise Http404

    def put(self, request, client_id):
        clients = self.get_object(client_id)
        clients.client_name = request.data.get('client_name', clients.client_name)
        clients.client_status = request.data.get('client_status', clients.client_status)
        clients.client_logo = request.data.get('client_logo', clients.client_logo)
        country_id = request.data.get('country_id')
        if country_id:
            country = Countries.objects.get(id_country=country_id)
            clients.country_id = country
        client_industri = request.data.get('client_industry')
        if client_industri:
            industry = Industry.objects.get(id_industry=client_industri)
            clients.client_industry = industry
        clients.save()

        data = {'message': 'Client changed successfully'}
        return JsonResponse(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# Delete one client
class DeleteOneClient(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = ClientsSerializer

    def delete(self, request, client_id, format=None):
        client = get_object_or_404(Clients, id_client=client_id)
        client.delete()
        return Response({'message': 'Client deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

######################################## Product CRUD ###################################################
# List of products
class ListProduct(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        produits = Produit.objects.all()
        data = {'products': list(produits.values())}
        return Response(data)

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
# list for product by client
class ProductListByClient(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = ProduitSerializer

    def get(self, request):
        user = request.user
        products = Produit.objects.filter(client_id=user.the_client.id_client)
        serialized_products = self.serializer_class(products, many=True)
        return Response(serialized_products.data)

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
# Detail for one product
class DetailOneProduct(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, product_id, format=None):

        try:
            produit = Produit.objects.get(id_product=product_id)
        except Produit.DoesNotExist:
            return JsonResponse({'error': "This Product does not exist"}, status=404)

        data = {
            'id_product': produit.id_product,
            'product_name': produit.product_name,
            'price': produit.product_price,
            'Icone': produit.product_picture.url if produit.product_picture else None,
            'client': produit.client_id,
            'pays': produit.country_id,
            'user': produit.user_id,
        }

        return JsonResponse(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
# Add one product
class AddOneProduct(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def post(self, request, *args, **kwargs):
        serializer = ProduitSerializer(data=request.data)
        if serializer.is_valid(raise_exception=False):
            product_data = serializer.validated_data
            product_obj = Produit.objects.create(
                product_picture=product_data['product_picture'],
                product_name=product_data['product_name'],
                product_price=product_data['product_price'],
                product_commission=product_data['product_commission'],
                country=product_data['country'],
                client=product_data['client'],
                training_p=product_data['training_p'],
            )
            data = {'message': 'Product successfully added'}
            return JsonResponse(data)
        else:
            errors = serializer.errors
            new_error = {}
            for field_name, field_errors in errors.items():
                new_error[field_name] = field_errors[0]
            return Response(new_error, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, format=None):
        return JsonResponse({'error': 'Unauthorized method'})
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# Update one product
class UpdateOneProduct(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self, product_id):
        try:
            return Produit.objects.get(id_product=product_id)
        except Produit.DoesNotExist:
            raise Http404

    def put(self, request, product_id):
        product = self.get_object(product_id)
        product.product_name = request.data.get('product_name', product.product_name)
        product.product_price = request.data.get('product_price', product.product_price)
        product.product_commission = request.data.get('product_commission', product.product_commission)
        country_id = request.data.get('country')
        if country_id:
            countries = Countries.objects.get(id_country=country_id)
            product.country = countries
        training_p = request.data.get('training_p')
        if training_p:
            trainings = Training.objects.get(id_training=training_p)
            product.training_p = trainings
        client_id = request.data.get('client')
        if client_id:
            clients = Clients.objects.get(id_client=client_id)
            product.client = clients
        product.product_picture = request.data.get('product_picture', product.product_picture)
        product.save()

        data = {'message': 'Product changed successfully'}
        return JsonResponse(data)

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# Delete one product
class DeleteOneProduct(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def delete(self, request, product_id, format=None):
        product = get_object_or_404(Produit, id_product=product_id)
        product.delete()
        return Response({'message': 'Product deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

######################################## Locality CRUD ###################################################
# add une locality
class AddOneLocality(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = LocalitySerializer(data=request.data)
        if serializer.is_valid(raise_exception=False):
            locality_data = serializer.validated_data
            locality_obj = Locality.objects.create(
                locality_name=locality_data['locality_name'],
                id_country=locality_data['id_country'],
            )
            data = {'message': 'Locality successfully added'}
            return JsonResponse(data)
        else:
            errors = serializer.errors
            new_error = {}
            for field_name, field_errors in errors.items():
                new_error[field_name] = field_errors[0]
            return Response(new_error, status=status.HTTP_400_BAD_REQUEST)
    def get(self, request, format=None):
        return JsonResponse({'error': 'Unauthorized method'})

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# list of locatities
class ListLocality(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        locality = Locality.objects.all()
        data = {
            'Localities': list(locality.values()),
        }
        return Response(data)

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
      
# details for one locality
class DetailOneLocality(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, locality_id, format=None):
        try:
            locality = Locality.objects.get(id_locality=locality_id)
        except Locality.DoesNotExist:
            return JsonResponse({'error': "This Locality does not exist."}, status=404)
        
        data = {
            'id_locality': locality.id_locality,
            'locality_name': locality.locality_name,
            'id_country': locality.id_country.id_country,
        }
        return JsonResponse(data)
        
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
# Delete one locality
class DeleteOneLocality(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def delete(self, request, locality_id, format=None):
        locality = get_object_or_404(Locality, id_locality=locality_id)
        locality.delete()
        return Response({'message': 'Locality deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# update one locality
class UpdateOneLocality(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self, locality_id):
        try:
            return Locality.objects.get(id_locality=locality_id)
        except Locality.DoesNotExist:
            raise Http404

    def put(self, request, locality_id):
        locality = self.get_object(locality_id)
        locality.locality_name = request.data.get('locality_name', locality.locality_name)
        country_id = request.data.get('id_country')
        if country_id:
            countries = Countries.objects.get(id_country=country_id)
            locality.id_country = countries
        locality.save()
        data = {'message': 'Locality changed successfully'}
        return JsonResponse(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

######################################## Industry CRUD ###################################################
# add one industry
class AddIndustry(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def post(self, request, format=None):
        serializer = IndustrySerializer(data=request.data)
        if serializer.is_valid(raise_exception=False):
            industry = serializer.save()
            if Industry.objects.filter(industry_name=industry.industry_name).exists():
                data = {'message': 'Industry successfully added'}
                return JsonResponse(data)
            else:
                industries = Industry.objects.create(
                    industry_name=industry.industry_name,
                )
                industries.save()
                # data = {'message': 'Industry successfully added'}
                return JsonResponse(data)
        else:
            errors = serializer.errors
            print(errors)
            data=json.dumps(errors)
            print(data)
            tab=[]
            default_errors = serializer.errors
            new_error = {}
            for field_name, field_errors in default_errors.items():
                new_error[field_name] = field_errors[0]
            return Response(new_error, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, format=None):
        return JsonResponse({'error': 'Unauthorized method'})

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# list of industry
class ListIndustry(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        industry = Industry.objects.all()
        data = {
            'Industries': list(industry.values()),
        }
        return Response(data)

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# details for one industry
class DetailOneIndustry(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, industry_id, format=None):

        try:
            industry = Industry.objects.get(id_industry=industry_id)
        except Industry.DoesNotExist:
            return JsonResponse({'error': "This Industry does not exist."}, status=404)

        data = {
            'id_industry': industry.id_industry,
            'industry_name': industry.industry_name,
            'industry_status': industry.industry_status,
        }
        return JsonResponse(data)
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
    
# Delete one industry
class DeleteOneIndustry(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def delete(self, request, industry_id, format=None):
        industry = get_object_or_404(Industry, id_industry=industry_id)
        industry.delete()
        return Response({'message': 'Industry deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# update one industry
class UpdateOneIndustry(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self, industry_id):
        try:
            return Industry.objects.get(id_industry=industry_id)
        except Industry.DoesNotExist:
            raise Http404

    def put(self, request, industry_id):
        industry = self.get_object(industry_id)
        industry.industry_name = request.data.get('industry_name', industry.industry_name)
        industry.industry_status = request.data.get('industry_status', industry.industry_status)
        industry.save()
        data = {'message': 'Industry changed successfully'}
        return JsonResponse(data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalid'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)










######################################## dashboard CRUD ###################################################
class DashboardView(generics.RetrieveUpdateAPIView):
    queryset = Dashboards.objects.all()
    serializer_class = DashboardsSerializer
    permission_classes = (IsAuthenticated,)

    def get_object(self):
        user = request.user
        if not user.is_superuser:
            try:
                privilege_admin = Privilege.objects.get(id=1)
            except Privilege.DoesNotExist:
                data = {'message':"Le privilège 'admin' n'existe pas."}
                return HttpResponse(data)

            if not user.privilege == privilege_admin:
                data = {'message':"Vous n'avez pas le droit de créer un utilisateur."}
                return HttpResponse(data)
        # Récupérer le tableau de bord correspondant à l'utilisateur actuel
        dashboard, created = Dashboards.objects.get_or_create(user=user)
        return dashboard

class CreateDashboardView(generics.CreateAPIView):
    serializer_class = DashboardsSerializer

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

######################################## Domaine CRUD ###################################################
class AjouterDomaine(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def post(self, request, format=None):
        domaine_name = request.POST.get('domaine_name', None)
        if not domaine_name:
            return HttpResponse("Le champ domaine_name est requis.")
        
        domaine = Domaine(
            domaine_name=domaine_name,
        )
        domaine.save()

        data = {'message': 'Domaine ajouté avec succès'}
        return JsonResponse(data)

    def get(self, request, format=None):
        return JsonResponse({'error': 'Méthode non autorisée'})

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalide'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

# list des domaines
class ListeDomaine(APIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        domaine = Domaine.objects.all()
        data = {
            'Domaines': list(domaine.values()),
        }
        return Response(data)

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalide'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
      
class TypeIDViewSet(viewsets.ModelViewSet):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    queryset = TypeID.objects.all()
    serializer_class = TypeIDSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('id_country',)

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalide'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

class TypeIDList(generics.ListAPIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    queryset = TypeID.objects.all()
    serializer_class = TypeIDSerializer

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalide'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

class TypeIDDetail(generics.RetrieveAPIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    queryset = TypeID.objects.all()
    serializer_class = TypeIDSerializer

    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalide'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

class TypeIDViewSets(viewsets.ViewSet):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request, id_country_id=None):
        queryset = TypeID.objects.filter(id_country=id_country_id)
        serializer = TypeIDSerializer(queryset, many=True)
        return Response(serializer.data)
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalide'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

class TypeIDDetail(generics.RetrieveAPIView):
    authentication_classes = [ExpiringTokenAuthentication]
    permission_classes = [IsAuthenticated]

    queryset = TypeID.objects.all()
    serializer_class = TypeIDSerializer
    def get_queryset(self):
        id_country = self.kwargs.get('id_country')
        if id_country:
            queryset = TypeID.objects.filter(id_country=id_country)
        else:
            queryset = TypeID.objects.all()
        return queryset
    
    def handle_exception(self, exc):
        data = {}
        if isinstance(exc, AuthenticationFailed):
            data['token_status'] = 'Token Invalide'
            return Response(data, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

class CountryViewSet(APIView):
    def get(self, request):
        countries = Countries.objects.all()
        serializer = CountrySerializer(countries, many=True)
        return Response(serializer.data)
        
    def post(self, request):
        serializer = CountrySerializer(data=request.data)

        if serializer.is_valid(raise_exception=False):
                    country = serializer.save()
                    return Response({"status": "ok", "message": f"Country {country.country_name} created"})
        else:
            errors = serializer.errors
            print(errors)
            data=json.dumps(errors)
            print(data)
            tab=[]
            default_errors = serializer.errors
            new_error = {}
            for field_name, field_errors in default_errors.items():
                new_error[field_name] = field_errors[0]

            return Response({"status": "nok", "message": new_error}, status=status.HTTP_400_BAD_REQUEST)
    
class clientsViewSet(viewsets.ModelViewSet):
    queryset = Clients.objects.all()
    serializer_class = ClientsSerializer
    filter_backends = (filters.DjangoFilterBackend,)

class EducationViewSet(viewsets.ModelViewSet):
    queryset = EducationLevel.objects.all()
    serializer_class = EducationSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('id_country',)

#curl -X POST http://localhost:8000/api/uploadImages/ -H "Content-Type: multipart/form-data" -b "cookie1=value1;cookie2=value2" -H "X-CSRFToken: GLafZcpiUT2sfwZwujowMWp0OtupUEcEZGNFgo7DtsLzgApRblL9pght8V6WlEYF" -F "file=@/Users/gillesgnanagbe/Desktop/Screenshot 2023-01-25 at 18.22.22.png“ 

def check_otp(request, token, otp):
    try:
        tp = TokenPin.objects.get(token=token)
    except TokenPin.DoesNotExist:
        return JsonResponse({'status':'404','error': 'Invalid token'}, status=404)
    if tp.pin != otp:
        return JsonResponse({'status':'401','error': 'Invalid OTP'}, status=401)
    return JsonResponse({'status':'200','message': 'OTP is valid'})

@api_view(['GET'])
def search_token_pin(request, token, pin,phone):
    count = TokenPin.objects.filter(token=token, pin=pin,phone_number=phone).count()
    return Response({'count': count}, status=status.HTTP_200_OK)

class PosExcelUploadViewSet(viewsets.ModelViewSet):
    serializer_class = PosSerializer
    queryset = Pos.objects.all()

    def create(self, request, *args, **kwargs):
        excel_file = request.FILES.get('file')
        if not excel_file:
            return Response({'error': 'Excel file is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            df = pd.read_excel(excel_file)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data=df.to_dict('records'), many=True)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        return Response({'message': 'Pos créer avec succès'}, status=status.HTTP_201_CREATED)
    queryset = Pos.objects.all()
    serializer_class = PosSerializer
    filter_backends = (filters.DjangoFilterBackend)

class FileViewSet(APIView):
  parser_classes = (MultiPartParser, FormParser)
  def post(self, request, *args, **kwargs):
    file_serializer = MediaSerializer(data=request.data)
    if file_serializer.is_valid():
      file_serializer.save()
      return Response(file_serializer.data, status=status.HTTP_201_CREATED)
    else:
      return Response(file_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
  
class UploadViewSet(ViewSet):
    serializer_class = UploadSerializer

    def list(self, request):
        return Response("GET API")

    def create(self, request):
        file_uploaded = request.FILES.get('file_uploaded')
        content_type = file_uploaded.content_type
        response = "POST API and you have uploaded a {} file".format(content_type)
        return Response(response)
    
def getToken(request):
    csrf_token = get_token(request)
    return JsonResponse({'status': csrf_token})
 
class EducationFilter(filters.FilterSet):
    id_country = filters.NumberFilter(field_name='id_country')
    class Meta:
        model = EducationLevel
        fields = ['id_country']
        
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

def upload_image(request):
    if request.method == 'POST':
        image = request.FILES['image']
        mymodel = Media(image=image)
        mymodel.save()
        return JsonResponse({'status': 'success'})
    else:
        return HttpResponse('Only POST method is allowed')

def generate_token_pin(request, phone_number):
    token = os.urandom(20).hex()
    pin = ''.join(random.choices(string.digits, k=4))
    token_pin = TokenPin.objects.create(phone_number=phone_number, token=token, pin=pin)
    return JsonResponse({"token": token, "pin": pin})

