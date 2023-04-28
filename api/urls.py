
from rest_framework.schemas import get_schema_view
from rest_framework import routers
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from django.urls import path, include
from django.conf.urls.static import static
from django.conf import settings
from .views import ListUser, AddIndustry, CountryViewSet,TypeIDViewSet,EducationViewSet,FileViewSet,AddOneFootsoldier,AddOneTarget,TargetList,AddOneLocality,TrainingClientList,DetailOneUser
from .views import TypeIDDetail, CustomLogout,AddOneKYC,ListKYC,UpdateOneKYC,DeleteOneKyc,AddOnePos,ListPos,CustomAuthToken,AjouterDomaine,ListPrivilege,FootsoldierListByClient,DeleteOneIndustry
from .views import UploadViewSet,ListClient,AddOneClient,UpdateOneClient,DeleteOneClient,DeleteOneProduct,ListFootsoldier,DeleteOneTarget,DeleteOneTraining,ListIndustry,ClientTargetsView,DetailOneIndustry
from .views import UpdateOneUser,AddOneTraining,UpdateOneProduct,UpdateOneFootsoldier,UpdateOneTypeId,ListTypeId,UpdateOneTraining,UpdateOneTarget,ClientUsersView,ProductListByClient,DeleteOneQuizExam,DetailOneProduct
from .views import PosExcelUploadViewSet,CreateOneUser,ListTraining,ListProduct,AddOneProduct,DeleteOneFootsoldier,AddOneTypeId,DeleteOneTypeId,UpdateOneSectionQuiz,DetailOneClient,DeleteOneQuiz,UpdateOneIndustry
from .views import AddOneCountries,UpdateOneCountries,DeleteOneCountries,ListCountries,AddOneEducationLevel,ListEducationLevel,UpdateOneEducationLevel,DeleteOneEducationLevel,ListQuizSection,ListLocality,UpdateOneLocality
from .views import AddOneSection,ListSection,UpdateOneSection,DeleteOneSection,AddOneChapter,ListChapter,UpdateOneChapter,DeleteOneChapter,AddOneQuizSection,AddOneAnswerSection,ExamCreate,ListeDomaine,ClientPosView,DeleteOneLocality
from .views import QuizExamList,ExamList,ListAnswerSection,UserExamCreate,UserExamList,AnswerExamList,AnswerExamCreate,UserScoreList,UserScoreCreate,DeleteOneUser,AddOneQuizExam,AddOnePrivilege,UpadateOneQuizExam,DetailOneLocality
from api.views import generate_token_pin,check_otp,upload_image,search_token_pin

schema_view = get_schema_view(
    openapi.Info(
        title="API Documentation",
        default_version='v1',
        description="API Documentation",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@xyz.com"),
        license=openapi.License(name="MIT License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

router = routers.DefaultRouter()
router.register(r'upload', UploadViewSet, basename="uploadNew")

# Wire up our API using automatic URL routing.
router1 = routers.DefaultRouter()
router1.register(r'typeids', TypeIDViewSet, basename='typeids')

urlpatterns = [

    # api list by swagger
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('', include(router1.urls)),

    # login API
    path('user-connection/', CustomAuthToken.as_view()),
    # logout API
    path('logout/', CustomLogout.as_view(), name='logout'),

    # super_users users_admin & users_reader CRUD API for Admin
    path('list-user/', ListUser.as_view(), name='list_user'),
    path('add-user/', CreateOneUser.as_view(), name='add_user'),
    path('detail-user/<int:user_id>/', DetailOneUser.as_view(), name='detail_user'),
    path('update-user/<int:user_id>/', UpdateOneUser.as_view(), name='update_user'),
    path('delete-user/<int:user_id>/', DeleteOneUser.as_view(), name='delete_user'),

    # super_users users_admin & users_reader CRUD API for Client
    path('list-userclient/', ClientUsersView.as_view(), name='list_user'),
    
    # settings setting_countries CRUD API
    path('add-country/', AddOneCountries.as_view(), name='add_country'),
    path('list-country/', ListCountries.as_view(), name='list_country'),
    path('update-country/<int:country_id>/', UpdateOneCountries.as_view(), name='update_country'),
    path('delete-country/<int:country_id>/', DeleteOneCountries.as_view(), name='delete_country'),

    # clients CRUD API
    path('list-client/', ListClient.as_view(), name='list_client'),
    path('add-client/', AddOneClient.as_view(), name='add_client'),
    # path('detail-client/<int:client_id>/', DetailOneClient.as_view(), name='detail_client'),
    path('update-client/<int:client_id>/', UpdateOneClient.as_view(), name='update_client'),
    path('delete-client/<int:client_id>/', DeleteOneClient.as_view(), name='delete_client'),

    # settings setting_typeID CRUD API
    path('add-typeid/', AddOneTypeId.as_view(), name='add_typeid'),
    path('update-typeid/<int:type_id>/', UpdateOneTypeId.as_view(), name='update_typeid'),
    path('list-typeid/', ListTypeId.as_view(), name='list_typeid'),
    path('delete-typeid/<int:type_id>/', DeleteOneTypeId.as_view(), name='delete_typeid'),

    # settings setting_privilege CRUD API
    path('add-privilege/', AddOnePrivilege.as_view(), name='add_privilege'),
    path('list-privilege/', ListPrivilege.as_view(), name='list_privilege'),

    # locality CRUD API
    path('add-locality/', AddOneLocality.as_view(), name='add_locality'),
    path('list-locality/', ListLocality.as_view(), name='list_locality'),
    path('detail-locality/<int:locality_id>/', DetailOneLocality.as_view(), name='detail_locality'),
    path('delete-locality/<int:locality_id>/', DeleteOneLocality.as_view(), name='delete_locality'),
    path('update-locality/<int:locality_id>/', UpdateOneLocality.as_view(), name='update_locality'),

    # industry CRUD API
    path('add-industry/', AddIndustry.as_view(), name='add_industry'),
    path('list-industry/', ListIndustry.as_view(), name='list_industry'),
    path('detail-industry/<int:industry_id>/', DetailOneIndustry.as_view(), name='detail_industry'),
    path('delete-industry/<int:industry_id>/', DeleteOneIndustry.as_view(), name='delete_industry'),
    path('update-industry/<int:industry_id>/', UpdateOneIndustry.as_view(), name='update_industry'),

    # settings setting_level CRUD API
    path('add-level/', AddOneEducationLevel.as_view(), name='add_level'),
    path('update-level/<int:education_id>/', UpdateOneEducationLevel.as_view(), name='update_level'),
    path('list-level/', ListEducationLevel.as_view(), name='list_level'),
    path('delete-level/<int:education_id>/', DeleteOneEducationLevel.as_view(), name='delete_level'),

    # produit CRUD API
    path('list-product/', ListProduct.as_view(), name='list_products'),
    path('add-product/', AddOneProduct.as_view(), name='add_product'),
    path('update-product/<int:product_id>/', UpdateOneProduct.as_view(), name='modifier_produit'),
    path('delete-product/<int:product_id>/', DeleteOneProduct.as_view(), name='delete_product'),
    path('detail-product/<int:product_id>/', DetailOneProduct.as_view(), name='detail_produit'),

    # list des produits par client
    path('list-produitbyclient/', ProductListByClient.as_view(), name='liste_produitbyclient'),

    # FootSoldiers CRUD API
    path('list-footsoldier/', ListFootsoldier.as_view(), name='list_footsoldier'),
    path('add-footsoldier/', AddOneFootsoldier.as_view(), name='add_footsoldier'),
    path('update-footsoldier/<int:footsoldiers_id>/', UpdateOneFootsoldier.as_view(), name='update_footsoldier'),
    path('delete-footsoldier/<int:footsoldiers_id>/', DeleteOneFootsoldier.as_view(), name='delete_footsoldier'),

    # list des footsoldiers par client
    path('list-footsoldierbyclient/', FootsoldierListByClient.as_view(), name='list_footsoldierbyclient'),

    #  KYC CRUD API
    path('add-kyc/', AddOneKYC.as_view(), name='add_kyc'),
    path('list-kyc/', ListKYC.as_view(), name='list_kyc'),
    path('update-kyc/<int:kyc_id>/', UpdateOneKYC.as_view(), name='update_kyc'),
    path('delete-kyc/<int:kyc_id>/', DeleteOneKyc.as_view(), name='delete_kyc'),

    # Target CRUD API
    path('add-target/', AddOneTarget.as_view(), name='add_target'),
    path('list-target/', TargetList.as_view(), name='list_target'),
    path('update-target/<int:target_id>/', UpdateOneTarget.as_view(), name='update_target'),
    path('delete-target/<int:target_id>/', DeleteOneTarget.as_view(), name='delete_target'),

    # list target of client
    path('list-targetclient/', ClientTargetsView.as_view(), name='list_targetclient'),

    # pos CRUD API
    path('add-pos/', AddOnePos.as_view(), name='add_pos'),
    path('list-pos/', ListPos.as_view(), name='list_pos'),

    # list pos of client
    path('list-posclient/', ClientPosView.as_view(), name='list_posclient'),

    # training CRUD API
    path('add-training/', AddOneTraining.as_view(), name='add_training'),
    path('list-training/', ListTraining.as_view(), name='list_training'),
    path('delete-training/<int:training_id>/', DeleteOneTraining.as_view(), name='delete_training'),
    path('update-training/<int:training_id>/', UpdateOneTraining.as_view(), name='update_training'),

    # training for client
    path('list-trainingforclient/', TrainingClientList.as_view(), name='liste_trainingforclient'),


    # Section CRUD API
    path('add-section/', AddOneSection.as_view(), name='add_section'),
    path('list-section/', ListSection.as_view(), name='liste_section'),
    path('update-section/<int:section_id>/', UpdateOneSection.as_view(), name='update_section'),
    path('delete-section/<int:section_id>/', DeleteOneSection.as_view(), name='delete_section'),

    # Chapters CRUD API
    path('add-chapter/', AddOneChapter.as_view(), name='add_chapter'),
    path('list-chapter/', ListChapter.as_view(), name='list_chapter'),
    path('update-chapter/<int:chapter_id>/', UpdateOneChapter.as_view(), name='update_chapter'),
    path('delete-chapter/<int:chapter_id>/', DeleteOneChapter.as_view(), name='delete_chapter'),

    # quiz section CRUD API
    path('add-quiz/', AddOneQuizSection.as_view(), name='add_quiz'),
    path('update-quiz/<int:quiz_section_id>/', UpdateOneSectionQuiz.as_view(), name='update_quiz'),
    path('list-quiz/', ListQuizSection.as_view(), name='list_quiz'),
    path('delete-quiz/<int:sectionquiz_id>/', DeleteOneQuiz.as_view(), name='delete_quiz'),

    # answer section CRUD APi
    path('add-answersection/', AddOneAnswerSection.as_view(), name='add_answersection'),
    path('list-answersection/', ListAnswerSection.as_view(), name='list_answersection'),

    # exam CRUD API
    path('add-exam/', ExamCreate.as_view(), name='add_exam'),
    path('list-exam/', ExamList.as_view(), name='list_exam'),

    # Quizexam CRUD API
    path('add-quizexam/', AddOneQuizExam.as_view(), name='add_quizexam'),
    path('list-quizexam/', QuizExamList.as_view(), name='list_quizexam'),
    path('update-quizexam/<int:quiz_id>/', UpadateOneQuizExam.as_view(), name='update_quizexam'),
    path('delete-quizexam/<int:quiz_id>/', DeleteOneQuizExam.as_view(), name='delete_quizexam'),

    # Userexam CRUD API
    path('add-userexam/', UserExamCreate.as_view(), name='add_userexam'),
    path('list-usersexam/', UserExamList.as_view(), name='list_userexam'),

    # Answerexam CRUD API
    path('add-answerexam/', AnswerExamCreate.as_view(), name='add_answerexam'),
    path('list-answerexam/', AnswerExamList.as_view(), name='list_answerexam'),









    # domaine CRUD API
    path('ajouter-domaine/', AjouterDomaine.as_view(), name='ajouter_domaine'),
    path('list-domaine/', ListeDomaine.as_view(), name='list_domaine'),

    path('pos-upload-excel/', PosExcelUploadViewSet.as_view({'post': 'create'}), name='pos-upload-excel'),
    path('typeid/<int:pk>/', TypeIDDetail.as_view(), name='typeid-detail'),
    path('search-token-pin/<str:token>/<str:pin>/<str:phone>/', search_token_pin, name='search_token_pin'),
    path('upload/', FileViewSet.as_view(),name='file-upload'),
    path('upload123/', include(router.urls)),
    path('countries/', CountryViewSet.as_view(), name='country-list'),
    path('educations/', EducationViewSet.as_view({'get': 'list', 'post': 'create'}), name='education-list'),
    path('educations/<int:pk>/', EducationViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='education-detail'),
    path('typepiece/', TypeIDViewSet.as_view({'get': 'list', 'post': 'create'}), name='education-list'),
    path('typepiece/<int:pk>/', TypeIDViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='education-detail'),
    path('generate_token_pin/<str:phone_number>', generate_token_pin),
    path('check_otp/<str:token>/<str:otp>', check_otp) ,
    path('uploadImages/', upload_image, name='upload'),
    
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
