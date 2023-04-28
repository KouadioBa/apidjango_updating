from django.db import models
from django.utils import timezone
from django.db.models import Sum
from django.dispatch import receiver
from django.db.models.signals import post_save
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, UserManager

# Pos Model
class Pos(models.Model):
    id_pos = models.AutoField(primary_key=True)
    pos_countrie = models.ForeignKey('Countries', on_delete=models.PROTECT, null=True, blank=True)
    pos_client = models.ForeignKey('Clients', on_delete=models.PROTECT, null=True, blank=True)
    pos_indication = models.IntegerField(null=False, blank=False, default='')
    pos_name = models.CharField(max_length=250, null=False, unique=True)
    pos_long = models.FloatField(null=False, blank=False)
    pos_lat = models.FloatField(null=False, blank=False)
    pos_active = models.IntegerField(null=False, blank=False)
    numb_pos = models.IntegerField(default=0)
    user = models.ForeignKey('User', on_delete=models.CASCADE, null=True, blank=True)

# Target Model
class Target(models.Model):
    id_target = models.AutoField(primary_key=True)
    target_countrie = models.ForeignKey('Countries', on_delete=models.PROTECT, null=True, blank=True)
    target_client = models.ForeignKey('Clients', on_delete=models.PROTECT, null=True, blank=True)
    target_zone = models.CharField(max_length=100, unique=True)
    target_month = models.CharField(max_length=100, unique=True)
    target_moderm = models.DecimalField(max_digits=8, decimal_places=3)
    target_routeurs = models.DecimalField(max_digits=8, decimal_places=3)
    target_airtelmoney = models.DecimalField(max_digits=8, decimal_places=3)
    user = models.ForeignKey('User', on_delete=models.CASCADE, null=True, blank=True)

# Media Model
class Media(models.Model):
    id_media = models.AutoField(primary_key=True)
    file = models.FileField(upload_to='./field360App/media/')
    remark = models.CharField(max_length=20)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return str(self.id_media)

# Domaine Model
class Domaine(models.Model):
    id_domaine = models.AutoField(primary_key=True)
    domaine_name = models.CharField(max_length=100, null=False, blank=False, unique=True)

    def __str__(self):
        return self.domaine_name

# Industry Model
class Industry(models.Model):
    id_industry = models.AutoField(primary_key=True)
    industry_name = models.CharField(max_length=100, null=False, blank=False, unique=True)
    industry_status = models.IntegerField(default=1)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.industry_name

# Footsoldiers Model
class Footsoldiers(models.Model):
    id_footsoldiers = models.AutoField(primary_key=True)
    footsoldiers_country = models.ForeignKey('Countries', on_delete=models.CASCADE, null=True, blank=True)
    footsoldiers_phonenumber= models.CharField(max_length=100, null=False, blank=False, unique=True)
    footsoldiers_fullname = models.CharField(max_length=100, null=False, blank=False, unique=True)
    footsoldiers_zone = models.CharField(max_length=100, null=False, blank=False)
    footsoldiers_clients = models.ForeignKey('Clients', on_delete=models.PROTECT, null=True, blank=True)
    footsoldiers_picture = models.ImageField(upload_to='./field360App/media/', null=True, blank=True)
    user = models.ForeignKey('User', on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return self.footsoldiers_fullname
      
# UsersClient Model
class UsersClient(models.Model):
    id_userclient = models.AutoField(primary_key=True)
    userclient_email = models.CharField(max_length=100, null=False, blank=False, unique=True)
    userclient_identifiant = models.CharField(max_length=100, null=False, blank=False, unique=True)
    userclient_name = models.CharField(max_length=100, null=False, blank=False, unique=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    country = models.ForeignKey('Countries', on_delete=models.PROTECT, null=True, blank=True)
    client = models.ForeignKey('Clients', on_delete=models.PROTECT, null=True, blank=True)
    profile_picture = models.ImageField(upload_to='./field360App/media/', null=True, blank=True)
    privilege = models.ForeignKey('Privilege', on_delete=models.PROTECT, null=True, blank=True)
    user = models.ForeignKey('User', on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return self.userclient_name
    
# Produit Model
class Produit(models.Model):
    id_product = models.AutoField(primary_key=True)
    product_picture = models.ImageField(upload_to='./field360App/media/', null=True, blank=True)
    product_name = models.CharField(max_length=100, null=False, blank=False)
    product_price = models.CharField(max_length=100, null=False, blank=False)
    product_commission = models.CharField(max_length=100, null=False, blank=False)
    timestamp = models.DateTimeField(auto_now_add=True)
    country = models.ForeignKey('Countries', on_delete=models.PROTECT, null=True, blank=True)
    client = models.ForeignKey('Clients', on_delete=models.PROTECT, null=True, blank=True)
    training_p = models.ForeignKey('Training', on_delete=models.PROTECT, null=True, blank=True)
    user = models.ForeignKey('User', on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return self.product_name

# Countries Model
class Countries(models.Model):
    id_country = models.AutoField(primary_key=True)
    country_name = models.CharField(max_length=100, null=False, blank=False, unique=True)
    country_prefixe = models.CharField(max_length=10, null=False, blank=False, unique=True)
    flag = models.ImageField(upload_to='./field360App/media/', default='')
    user = models.ForeignKey('User', on_delete=models.CASCADE, null=True, blank=True)
    numbers_of_clients = models.IntegerField(default=0, editable=False)

    def __str__(self):
        return self.country_name

# clients Model
class Clients(models.Model):
    id_client = models.AutoField(primary_key=True)
    country_id = models.ForeignKey(Countries, on_delete=models.DO_NOTHING)
    client_logo = models.ImageField(upload_to='./field360App/media/', null=True, blank=True)
    client_industry = models.ForeignKey(Industry, on_delete=models.DO_NOTHING)
    client_name = models.CharField(max_length=20, unique=True)
    client_status = models.CharField(max_length=20)
    timestamp = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey('User', on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return self.client_name
    
    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        country = self.country_id
        country.numbers_of_clients = Clients.objects.filter(country_id=country).count()
        country.save()

class TypeID(models.Model):
    id_type = models.AutoField(primary_key=True)
    id_country = models.ForeignKey(Countries, on_delete=models.DO_NOTHING)
    id_name = models.CharField(max_length=100, null=False, blank=False)
    number_typeid = models.IntegerField(default=0)
    user = models.ForeignKey('User', on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return f"{self.id_country.country_name} - {self.id_name}"

# EducationLevel Model
class EducationLevel(models.Model):
    id_education = models.AutoField(primary_key=True)
    id_country = models.ForeignKey('Countries', on_delete=models.CASCADE)
    level_name = models.CharField(max_length=100, null=False, blank=False)
    level_number = models.IntegerField(default=0)
    user = models.ForeignKey('User', on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return f"{self.id_country.country_name} - {self.level_name}"

# Training Model
class Training(models.Model):
    id_training = models.AutoField(primary_key=True)
    id_client = models.ForeignKey(Clients, on_delete=models.CASCADE)
    produit_id = models.ForeignKey(Produit, on_delete=models.CASCADE)
    training_name = models.CharField(max_length=100, null=False, blank=False)
    training_onBoarding = models.BooleanField(default=True)
    training_min_score = models.FloatField(default=0)
    training_description = models.TextField()
    training_mode = models.IntegerField(default=0)
    training_statut = models.IntegerField(default=0)
    training_category = models.CharField(max_length=100, null=False, blank=False, default='')
    countrie_id = models.ForeignKey(Countries, on_delete=models.CASCADE, default='')
    user = models.ForeignKey('User', on_delete=models.CASCADE, null=True, blank=True)


    def __str__(self):
        return f"{self.id_client.country_name} - {self.training_name}"

# Sections Model
class Sections(models.Model):
    id_section = models.AutoField(primary_key=True)
    id_formation = models.ForeignKey(Training, on_delete=models.CASCADE)
    sections_order = models.ForeignKey(Produit, on_delete=models.CASCADE)
    sections_name = models.CharField(max_length=100, null=False, blank=False)
    user = models.ForeignKey('User', on_delete=models.CASCADE, null=True, blank=True)


# QuizSection Model
class QuizSection(models.Model):
    id_quiz_section = models.AutoField(primary_key=True)
    id_section = models.ForeignKey(Sections, on_delete=models.CASCADE)
    quiz_question_name = models.CharField(max_length=100, null=False, blank=False)
    quiz_question_points = models.IntegerField(default=0)
    quiz_question_type = models.CharField(max_length=100, null=False, blank=False)
    quiz_question_media = models.ImageField(upload_to='./field360App/media/', null=True, blank=True)
    quiz_description = models.TextField()
    user = models.ForeignKey('User', on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return f" {self.id_section.sections_name} - {self.quiz_question_name}"

# Chapters Model
class Chapters(models.Model):
    id_chapter = models.AutoField(primary_key=True)
    id_section = models.ForeignKey(Sections, on_delete=models.CASCADE)
    chapter_order = models.CharField(max_length=100, null=False, blank=False)
    chapter_name = models.CharField(max_length=100, null=False, blank=False)
    chapter_description = models.TextField()
    media = models.ImageField(upload_to='./field360App/media/', null=True, blank=True)
    user = models.ForeignKey('User', on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return f"{self.id_section.sections_name} - {self.chapitres_name}"

# Exam Model
class Exam(models.Model):
    id_examen = models.AutoField(primary_key=True)
    id_training = models.ForeignKey(Training, on_delete=models.CASCADE)
    exam_order = models.CharField(max_length=100, null=False, blank=False)
    exam_name = models.CharField(max_length=100, null=False, blank=False)
    exam_description = models.TextField()
    user = models.ForeignKey('User', on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return f"{self.id_training.formation_name} - {self.examen_name}"

# id_quiz_examen,id_examen,quiz_question_name,quiz_question_points,quiz_question_type,quiz_question_media,examen_description
class QuizExamen(models.Model):
    id_quiz_examen = models.AutoField(primary_key=True)
    id_examen = models.ForeignKey(Exam, on_delete=models.CASCADE)
    quiz_question_name = models.CharField(max_length=100, null=False, blank=False)
    quiz_question_points = models.IntegerField(default=0)
    quiz_question_type = models.CharField(max_length=100, null=False, blank=False)
    quiz_question_media = models.ImageField(upload_to='./field360App/media/', default='')
    quiz_description = models.TextField()
    user = models.ForeignKey('User', on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return f"{self.id_examen.exam_name} - {self.quiz_question_name}"

# Privilege Model
class Privilege(models.Model):
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField()

    class Meta:
        db_table = 'privilege'
        verbose_name = 'Privilege'
        verbose_name_plural = 'Privileges'

    def __str__(self):
        return self.name

# AnswersExamen Model
class AnswersExamen(models.Model):
    id_answer_examen = models.AutoField(primary_key=True)
    id_quiz_examen = models.ForeignKey(QuizExamen, on_delete=models.CASCADE)
    answer_label = models.TextField()
    answer_correct = models.BooleanField(default=False)
    user = models.ForeignKey('User', on_delete=models.PROTECT, null=True, blank=True)

    def __str__(self):
        return f"{self.id_quiz.quiz_question_name} - {self.answer_label}"

# AnswersSection Model
class AnswersSection(models.Model):
    id_answer_section = models.AutoField(primary_key=True)
    id_quiz = models.ForeignKey(QuizSection, on_delete=models.CASCADE, related_name='id_QuizSection_id')
    answer_label = models.TextField()
    answer_correct = models.BooleanField(default=False)
    user = models.ForeignKey('User', on_delete=models.PROTECT, null=True, blank=True)
    def __str__(self):
        return f"{self.id_quiz.quiz_question_name} - {self.answer_label}"

# Locality Model
class Locality(models.Model):
    id_locality = models.AutoField(primary_key=True)
    id_country = models.ForeignKey(Countries, on_delete=models.DO_NOTHING)
    locality_name = models.CharField(max_length=100, null=False, blank=False)
    def __str__(self):
        return f"{self.locality_name}"

# UserExam Model
class UserExam(models.Model):
    id_user_exam = models.AutoField(primary_key=True)
    id_quiz = models.ForeignKey(QuizExamen, on_delete=models.DO_NOTHING)
    choice = models.CharField(max_length=100, null=False, blank=False)
    answer = models.BooleanField(default=False)
    user = models.ForeignKey('User', on_delete=models.PROTECT, null=True, blank=True)

    def __str__(self):
        return f" {self.id_quiz.quiz_question_name} - {self.choice}"

# UserQuiz Model
class UserQuiz(models.Model):
    id_user_quiz = models.AutoField(primary_key=True)
    id_quiz = models.ForeignKey(QuizSection, on_delete=models.DO_NOTHING)
    choice = models.CharField(max_length=100, null=False, blank=False)
    answer = models.BooleanField(default=False)

    def __str__(self):
        return f" {self.id_quiz.quiz_question_name} - {self.choice}"

# dashboards model  
class Dashboards(models.Model):
    id_dashboard = models.AutoField(primary_key=True)
    dashboard_name = models.CharField(max_length=255)
    refresh_frequency = models.CharField(max_length=255)

    def __str__(self):
        return self.dashboard_name   

# User model
class User(AbstractBaseUser, PermissionsMixin):
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(default=timezone.now, null=False, blank=True)
    email = models.EmailField(('email'), null=False, blank=True)
    nom = models.CharField(max_length=50, null=False, blank=True, default='')
    prenoms = models.CharField(max_length=100, null=False, blank=True, default='')
    niveau_education = models.ForeignKey(EducationLevel, on_delete=models.DO_NOTHING,related_name='niveau_education_id', null=True)
    localite = models.ForeignKey(Locality, on_delete=models.DO_NOTHING, related_name='localite_id', null=True)
    country = models.ForeignKey(Countries, on_delete=models.DO_NOTHING, related_name='pays_id', null=True)
    username = models.CharField(max_length=20, blank=False, unique=True, default='')
    password = models.CharField(max_length=255)
    profile_picture = models.ImageField(upload_to='./field360App/media/', null=True, blank=True)
    numero = models.CharField(max_length=20, blank=False, unique=True, default='')
    date_naissance = models.DateField(null=False, blank=True, default=timezone.now)
    lieu_naissance = models.CharField(max_length=50, null=True, blank=True, default='')
    type_piece = models.ForeignKey(TypeID, on_delete=models.DO_NOTHING, related_name='type_piece_id', null=True)
    numero_piece = models.CharField(max_length=50, null=True, blank=True, default='')
    date_expiration = models.DateField(null=False, blank=True, default=timezone.now)
    piece_recto = models.ImageField(upload_to='./field360App/media/', null=True, blank=True)
    piece_verso = models.ImageField(upload_to='./field360App/media/', null=True, blank=True)
    privilege = models.ForeignKey('Privilege', on_delete=models.PROTECT, null=True, blank=True)
    create_by = models.ForeignKey('User', on_delete=models.PROTECT, null=True, blank=True)
    the_client = models.ForeignKey(Clients, on_delete=models.CASCADE, null=True, blank=True, related_name='users')
    account_validated = models.BooleanField(default=False)
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['nom', 'prenoms']
    objects = UserManager()                                                                                     

    def __str__(self):
        return f"{self.nom} {self.prenoms}"

# PisteAudite model
class PisteAudite(models.Model):
    id_piste_audit = models.AutoField(primary_key=True)
    client = models.FileField(blank=False, null=False)
    userId = models.ForeignKey(User, on_delete=models.DO_NOTHING, related_name='user_piste_audit_id', null=True)
    details_actions = models.CharField(max_length=20)
    timestamp = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return self.id_piste_audit

# TokenPin model
class TokenPin(models.Model):
    phone_number = models.CharField(max_length=20)
    token = models.CharField(max_length=40, unique=True)
    pin = models.CharField(max_length=4, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return self.token

# Kyc model
class Kyc(models.Model):
    kycAgentid = models.ForeignKey(User, on_delete=models.DO_NOTHING, related_name='kyc_agent_id', null=True)
    userId = models.ForeignKey(User, on_delete=models.DO_NOTHING, related_name='user_agent_id', null=True)
    createdAt = models.DateTimeField(default=timezone.now, null=False, blank=True)
    email = models.EmailField(('email address'), null=False, blank=True)
    nom = models.CharField(max_length=50, null=False, blank=True, default='')
    prenoms = models.CharField(max_length=100, null=False, blank=True, default='')
    niveau_education = models.ForeignKey(EducationLevel, on_delete=models.DO_NOTHING,related_name='kyc_niveau_education_id', null=True)
    localite = models.ForeignKey(Locality, on_delete=models.DO_NOTHING, related_name='kyc_localite_id', null=True)
    pays = models.ForeignKey(Countries, on_delete=models.DO_NOTHING, related_name='kyc_pays_id', null=True)
    username = models.CharField(max_length=20, blank=False, unique=True, default='')
    date_naissance = models.DateField(null=False, blank=True, default=timezone.now)
    lieu_naissance = models.CharField(max_length=50, null=True, blank=True, default='')
    type_piece = models.ForeignKey(TypeID, on_delete=models.DO_NOTHING, related_name='kyc_type_piece_id', null=True)
    numero_piece = models.CharField(max_length=50, null=True, blank=True, default='')
    date_expiration = models.DateField(null=False, blank=True, default=timezone.now)
    photo_selfie = models.ImageField(upload_to='./field360App/media/', null=True, blank=True)
    piece_recto = models.ImageField(upload_to='./field360App/media/', null=True, blank=True)
    piece_verso = models.ImageField(upload_to='./field360App/media/', null=True, blank=True)
    isNomOk = models.BooleanField(default=False)
    isPrenomOk = models.BooleanField(default=False)
    isTypepPieceOk = models.BooleanField(default=False)
    isDateNaissanceOk = models.BooleanField(default=False)
    isLieuNaissanceOk = models.BooleanField(default=False)
    isTypePieceOk = models.BooleanField(default=False)
    isNumeroPieceOk = models.BooleanField(default=False)
    isDateExpirationOk = models.BooleanField(default=False)
    isPhotoSelfieOk = models.BooleanField(default=False)
    isPieceRectoOk = models.BooleanField(default=False)
    isPieceVersoOk = models.BooleanField(default=False)
    isAllok= models.BooleanField(default=False)
    clients_kyc = models.ForeignKey('Clients', on_delete=models.PROTECT, null=True, blank=True)
    user = models.ForeignKey('User', on_delete=models.PROTECT, null=True, blank=True)

    def __str__(self):
        return "{}".format(self.nom)

# UserScoreExam model
class UserScoreExam(models.Model):
    id_user_score = models.AutoField(primary_key=True)
    id_exam = models.ForeignKey(Exam, on_delete=models.DO_NOTHING)
    user = models.ForeignKey(User, on_delete=models.DO_NOTHING)
    score = models.DecimalField(decimal_places=2,max_digits=10)
    nombredepoints = models.IntegerField()
    results = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.results}"

# UserScoreQuiz model
class UserScoreQuiz(models.Model):
    id_user_score = models.AutoField(primary_key=True)
    id_quiz = models.ForeignKey(QuizSection, on_delete=models.DO_NOTHING)
    user = models.ForeignKey(User, on_delete=models.DO_NOTHING)
    score = models.DecimalField(decimal_places=2,max_digits=10)
    nombredepoints = models.IntegerField()
    results = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.id_user.nom} {self.id_user.prenoms} - {self.id_exam.exam_name} - {self.results}"