import django_filters
from .models import EducationLevel,Locality,TypeID,QuizExamen,AnswersExamen,QuizSection,AnswersSection

class EducationFilter(django_filters.FilterSet):
    class Meta:
        model = EducationLevel
        fields = ['id_country']

class LocalityFilter(django_filters.FilterSet):
    class Meta:
        model = Locality
        fields = ['id_country']
        
class TypeIDFilter(django_filters.FilterSet):
    class Meta:
        model = TypeID
        fields = ['id_country']