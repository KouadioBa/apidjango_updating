from rest_framework import serializers
from rest_framework.serializers import Serializer, FileField
from .models import User, Countries,EducationLevel,Locality,TypeID,Media,QuizExamen,AnswersExamen,QuizSection ,AnswersSection,Dashboards,Footsoldiers,Produit,Target,UserExam,UserScoreExam
from .models import User,Media,Countries,TypeID,Clients,Chapters, EducationLevel, Locality,TokenPin,Kyc, Industry,Produit,Pos,Training,Chapters,Sections,Exam,Domaine,UsersClient,Privilege

# privilege serializer
class PrivilegeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Privilege
        fields = ('name','description')
        extra_kwargs = {
            'name': {'write_only': True},
            'description': {'write_only': True},
        }
        

class MediaSerializer(serializers.ModelSerializer):
      class Meta():
        model = Media
        fields = ('id_media','file', 'remark', 'timestamp')
    
# Serializers define the API representation.
class UploadSerializer(Serializer):
    file_uploaded = FileField()
    class Meta:
        fields = ['file_uploaded']

# user serializer 
class UserSerializer(serializers.ModelSerializer):
    class Meta():
        model = User
        fields = '__all__'
        extra_kwargs = {
            'password': {'write_only': True}, 
            'profile_picture': {'required': True},
            'email': {'required': True},
            'nom': {'required': True},
            'prenoms': {'required': True},
            'username': {'required': True},
            'niveau_education': {'required': True},
            'country': {'required': True},
            'numero': {'required': True},
            'date_naissance': {'required': True},
            'type_piece': {'required': True},
            'numero_piece': {'required': True},
            'date_expiration': {'required': True},
            'piece_recto': {'required': True},
            'piece_verso': {'required': True},
            'privilege': {'required': True},
            'the_client': {'required': True}
            }

    def create(self, validated_data):
        user = User(
            username=validated_data['username'],
            email=validated_data['email'],
            prenoms=validated_data['prenoms'],
            date_naissance=validated_data['date_naissance'],
            numero=validated_data['numero'],
            nom=validated_data['nom'],
            privilege = validated_data['privilege'],
        )
        user.set_password(validated_data['password'])
        user.profile_picture = validated_data.get('profile_picture')
        user.save()
        return user
    
# dashboard serializer
class DashboardsSerializer(serializers.ModelSerializer):
    user = serializers.ReadOnlyField(source='user.username')

    class Meta:
        model = Dashboards
        fields = ('id', 'user', 'dashboard_name', 'refresh_frequency')
        read_only_fields = ('id',)

# client serializer
class ClientsSerializer(serializers.ModelSerializer):
    # created_by = serializers.PrimaryKeyRelatedField(read_only=True)
    class Meta:
        model = Clients
        fields = '__all__'
        extra_kwargs = {
            'client_logo': {'required': True},
        }


class CountrySerializer(serializers.ModelSerializer):
    class Meta:
        model = Countries
        fields = ('id_country', 'country_name', 'country_prefixe', 'flag')

class EducationSerializer(serializers.ModelSerializer):
    class Meta:
        model = EducationLevel
        fields = '__all__'
        extra_kwargs = {
            'level_name': {'required': True},
            'id_country': {'required': True},
            'level_number': {'required': True},
        }

class LocalitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Locality
        fields = ('id_locality', 'locality_name', 'id_country')
        extra_kwargs = {
            'locality_name': {'required': True},
            'id_country': {'required': True},
        }

class TypeIDSerializer(serializers.ModelSerializer):
    class Meta:
        model = TypeID
        fields = '__all__'
        extra_kwargs = {
            'id_name': {'required': True},
            'id_country': {'required': True},
            'number_typeid': {'required': True},
        }

class TargetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Target
        fields = '__all__'

class UserExamSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserExam
        fields = '__all__'
        extra_kwargs = {
            'id_quiz': {'required': True},
            'choice': {'required': True},
            'answer': {'required': True},
            'user': {'required': True},
        }

class FootsoldiersSerializer(serializers.ModelSerializer):
    footsoldiers_clients = serializers.PrimaryKeyRelatedField(
        queryset=Clients.objects.all(),
        required=True,
        error_messages={'required': 'This field is required.'}
    )
    footsoldiers_country = serializers.PrimaryKeyRelatedField(
        queryset=Countries.objects.all(),
        required=True,
        error_messages={'required': 'This field is required.'}
    )
    class Meta:
        model = Footsoldiers
        fields = '__all__'
        extra_kwargs = {
            'footsoldiers_picture': {'required': True},
        }

class QuizExamenSerializer(serializers.ModelSerializer):
    class Meta:
        model = QuizExamen
        fields = '__all__'
        extra_kwargs = {
            'id_examen': {'required': True},
            'quiz_question_name': {'required': True},
            'quiz_question_points': {'required': True},
            'quiz_question_type': {'required': True},
            'quiz_question_media': {'required': True},
            'quiz_description': {'required': True},
        }

class UserScoreExamSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserScoreExam
        fields = '__all__'
           
    
class AnswersExamenSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnswersExamen
        fields = '__all__'
        extra_kwargs = {
            'id_quiz_examen': {'required': True},
            'answer_label': {'required': True},
            'answer_correct': {'required': True},
        } 
    
class UserExamenSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserExam
        fields = '__all__'

class QuizSectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = QuizSection
        fields = '__all__'
        extra_kwargs = {
            'quiz_question_media': {'required': True},
            'quiz_question_points': {'required': True},
            'id_section': {'required': True},
        }

class AnswersSectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnswersSection
        fields = ('id_answer_section', 'id_quiz', 'answer_label','answer_correct')
        extra_kwargs = {
            'answer_correct': {'required': True}
        }

class TrainingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Training
        fields = '__all__'

class UsersClientSerializer(serializers.ModelSerializer):
    class Meta:
        model = UsersClient
        fields = '__all__'

class ProduitSerializer(serializers.ModelSerializer):
    client = serializers.PrimaryKeyRelatedField(
        queryset=Clients.objects.all(),
        required=True,
        error_messages={'required': 'This field is required.'}
    )
    country = serializers.PrimaryKeyRelatedField(
        queryset=Countries.objects.all(),
        required=True,
        error_messages={'required': 'This field is required.'}
    )
    training_p = serializers.PrimaryKeyRelatedField(
        queryset=Training.objects.all(),
        required=True,
        error_messages={'required': 'This field is required.'}
    )
    class Meta:
        model = Produit
        fields = '__all__'
        extra_kwargs = {
            'product_name': {'required': True},
            'product_price': {'required': True},
            'product_commission': {'required': True},
            'product_picture': {'required': True},
        }

class DomaineSerializer(serializers.ModelSerializer):
    class Meta:
        model = Domaine
        fields = '__all__'
        
class PosSerializer(serializers.ModelSerializer):
    class Meta:
        model = Pos
        fields = '__all__'
        
class TrainingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Training
        fields = '__all__'
        extra_kwargs = {
            'id_client': {'required': True},
            'countrie_id': {'required': True},
            'produit_id': {'required': True},
            'training_name': {'required': True},
            'training_onBoarding': {'required': True},
            'training_min_score': {'required': True},
            'training_description': {'required': True},
            'training_mode': {'required': True},
            'training_statut': {'required': True},
            'training_category': {'required': True},
        }
 
class ChaptersSerializer(serializers.ModelSerializer):
    class Meta:
        model = Chapters
        fields = '__all__'
        extra_kwargs = {
            'media': {'required': True},
        }

class SectionsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sections
        fields = '__all__'

class ExamSerializer(serializers.ModelSerializer):
    class Meta:
        model = Exam
        fields = '__all__'

class KycSerializer(serializers.ModelSerializer):
    class Meta:
        model = Kyc
        fields = '__all__'
        extra_kwargs = {
            'email': {'required': True},
            'nom': {'required': True},
            'prenoms': {'required': True},
            'username': {'required': True},
            'niveau_education': {'required': True},
            'localite': {'required': True},
            'pays': {'required': True},
            'numero': {'required': True},
            'date_naissance': {'required': True},
            'lieu_naissance': {'required': True},
            'type_piece': {'required': True},
            'numero_piece': {'required': True},
            'date_expiration': {'required': True},
            'piece_recto': {'required': True},
            'piece_verso': {'required': True},
            'photo_selfie': {'required': True}
            }

class IndustrySerializer(serializers.ModelSerializer):
    class Meta:
        model = Industry
        fields = '__all__'

class TokenPinSerializer(serializers.ModelSerializer):
    class Meta:
        model = TokenPin
        fields = '__all__'
