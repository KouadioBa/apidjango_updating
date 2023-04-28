from django.contrib import admin
from .models import AnswersSection,User,Media,Countries,TypeID,Clients,UserScoreQuiz,Chapters,QuizExamen,AnswersExamen,QuizSection, EducationLevel, Locality,TokenPin,Kyc, Industry,Pos,Training,Chapters,Sections,Exam

from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin

class MyUserAdmin(UserAdmin):
        fieldsets = (
	    (None, {'fields': ('username','email', 'password')}),
	    (_('Personal info'), {'fields': ('nom', 'prenoms')}),
	    (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
		(_('user_info'), {'fields': ('niveau_education','lieu_naissance','date_naissance')}),
  		(_('user_identification'), {'fields': ('type_piece','date_expiration','photo_selfie','piece_recto','piece_verso')}),
    	(_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser','groups', 'user_permissions')}),
         )
        add_fieldsets = (
	    (None, {
		'classes': ('wide', ),
		'fields': ('email', 'password1', 'password2'),
    	}),
        )

        list_display = ["username",'email', 'nom', 'prenoms', 'is_staff']
        search_fields = ('email', 'nom', 'prenoms',  "username")
        ordering = ('date_joined',"username" )

admin.site.register(User, MyUserAdmin)

#admin.site.register(Media)

class MediaAdmin(admin.ModelAdmin):
    list_display = ( 'id_media', 'file','remark','timestamp')
    list_filter = ('timestamp',)
    search_fields = ('remark',)
admin.site.register(Media, MediaAdmin)

class CountryAdmin(admin.ModelAdmin):
    list_display = ( 'id_country', 'country_name','country_prefixe')
    list_filter = ('id_country',)
    search_fields = ('level_name',)
admin.site.register(Countries, CountryAdmin)

class TypeIDAdmin(admin.ModelAdmin):
    list_display = ( 'id_type','id_country','id_name','number_typeid')
    list_filter = ('id_country',)
    search_fields = ('id_name',)
admin.site.register(TypeID, TypeIDAdmin)

class EducationAdmin(admin.ModelAdmin):
    list_display = ( 'id_education','id_country','level_name','level_number')
    list_filter = ('id_country',)
    search_fields = ('level_name',)
admin.site.register(EducationLevel, EducationAdmin)

class TokenPinAdmin(admin.ModelAdmin):
    list_display = ( 'phone_number','token','pin','created_at')
    list_filter = ('created_at',)
    search_fields = ('phone_number','token')
admin.site.register(TokenPin, TokenPinAdmin)
        
class LocalityAdmin(admin.ModelAdmin):
    list_display = ('id_locality', 'id_country','locality_name')
    list_filter = ('id_country',)
    search_fields = ('locality_name','id_country')
admin.site.register(Locality, LocalityAdmin)

class KycAdmin(admin.ModelAdmin):
    list_display =  ('kycAgentid', 'userId', 'createdAt',  'email' , 'nom',  'prenoms', 'niveau_education', 'localite', 'pays',   'username', 
    'date_naissance', 'lieu_naissance',   'type_piece',  'numero_piece',  'date_expiration', 
    'photo_selfie',     'piece_recto',     'piece_verso', 
    'isNomOk', 'isPrenomOk', 'isTypepPieceOk',  'isDateNaissanceOk', 'isLieuNaissanceOk','isTypePieceOk',
    'isNumeroPieceOk',  'isDateExpirationOk', 'isPhotoSelfieOk', 'isPieceRectoOk', 
    'isPieceVersoOk' )
    list_filter = ('pays',)
    search_fields = ('username','localite')
admin.site.register(Kyc, KycAdmin)


class SectionAdmin(admin.ModelAdmin):
    list_display =  ('id_section','id_formation','sections_order', 'sections_name' )
    list_filter = ('id_formation',)
    search_fields = ('sections_name',)
admin.site.register(Sections, SectionAdmin)

class IndustryAdmin(admin.ModelAdmin):
    list_display =  ('id_industry','industry_name','industry_status','timestamp' )
    list_filter = ('id_industry',)
    search_fields = ('industry_name',)
admin.site.register(Industry, IndustryAdmin)

# class ProductAdmin(admin.ModelAdmin):
#     list_display =  ('id_product','product_icone','product_name','product_price','product_commission','timestamp' )
#     list_filter = ('id_product',)
#     search_fields = ('product_name',)
# admin.site.register(Products, ProductAdmin)

class PosAdmin(admin.ModelAdmin):
    list_display = ('id_pos', 'pos_client', 'pos_name', 'pos_long', 'pos_lat', 'pos_active')
    list_filter = ('pos_countrie',)
    search_fields = ('pos_name',)
admin.site.register(Pos, PosAdmin)

class ClientsAdmin(admin.ModelAdmin):
    list_display =  ('id_client','country_id','client_logo','client_industry','client_name','client_status','timestamp')
    list_filter = ('id_client',)
    search_fields = ('client_name',)
admin.site.register(Clients, ClientsAdmin)

class AnswersSectionAdmin(admin.ModelAdmin):
    list_display =('id_answer_section','id_quiz','answer_label','answer_correct')
    list_filter = ('id_answer_section',)
    search_fields = ('answer_label',)
admin.site.register(AnswersSection, AnswersSectionAdmin)

class AnswersExamenAdmin(admin.ModelAdmin):
    list_display =  ('id_answer_examen','id_quiz_examen','answer_label','answer_correct')
    list_filter = ('id_answer_examen',)
    search_fields = ('answer_label',)
admin.site.register(AnswersExamen, AnswersExamenAdmin)

class TrainingAdmin(admin.ModelAdmin):
    list_display =  ('id_training','id_client','produit_id','training_name','training_onBoarding','training_min_score','training_description')
    list_filter = ('id_training',)
    search_fields = ('formation_name',)
admin.site.register(Training, TrainingAdmin)

class QuizSectionAdmin(admin.ModelAdmin):
    list_display =  ('id_quiz_section','id_section','quiz_question_name','quiz_question_type','quiz_question_media','quiz_description')
    list_filter = ('id_quiz_section',)
    search_fields = ('quiz_question_name',)
admin.site.register(QuizSection, QuizSectionAdmin)

class QuizExamenAdmin(admin.ModelAdmin):
    list_display =  ('id_quiz_examen','id_examen','quiz_question_name','quiz_question_points','quiz_question_type','quiz_question_media','quiz_description')
    list_filter = ('id_quiz_examen',)
    search_fields = ('quiz_question_name',)
admin.site.register(QuizExamen, QuizExamenAdmin)

class ChaptersAdmin(admin.ModelAdmin):
    list_display =  ('id_chapter','id_section','chapter_order','chapter_name','chapter_description')
    list_filter = ('id_chapter',)
    search_fields = ('chapter_name',)
admin.site.register(Chapters, ChaptersAdmin)

class ExamAdmin(admin.ModelAdmin):
    list_display =  ('id_examen','id_training','exam_order','exam_name','exam_description')
    list_filter = ('id_examen',)
    search_fields = ('exam_name',)
admin.site.register(Exam, ExamAdmin)

class UserScoreQuizAdmin(admin.ModelAdmin):
    list_display =  ('id_user_score','id_quiz','user','score','nombredepoints','results')
    list_filter = ('id_user_score',)
    search_fields = ('id_user',)
admin.site.register(UserScoreQuiz, UserScoreQuizAdmin)