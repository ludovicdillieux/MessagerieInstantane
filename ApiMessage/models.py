from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)


class CustomUserManager(BaseUserManager):
    def create_user(self, username, password, **extra_fields):
        if not username:
            raise ValueError("The Username field must be set")
        user = self.model(username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, password, **extra_fields):
        extra_fields.setdefault("role", "admin")
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(username, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(unique=True, max_length=255)
    role = models.CharField(
        max_length=50, choices=[("admin", "Admin"), ("user", "User")], default="user"
    )
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_creation = models.DateTimeField(auto_now_add=True)

    objects = CustomUserManager()

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.username

    def has_perm(self, perm, obj=None):
        return self.is_staff

    def has_module_perms(self, app_label):
        return self.is_staff


class GroupeConversation(models.Model):
    nom = models.CharField(max_length=255)
    user = models.ManyToManyField(CustomUser)

    def __str__(self):
        return self.nom


# class MembreGroupeConversation(models.Model):
#     id = models.AutoField(primary_key=True)
#     user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
#     groupe_conversation = models.ForeignKey(
#         GroupeConversation, on_delete=models.CASCADE
#     )
#     date_creation = models.DateTimeField(auto_now_add=True)
    
#     def get_user_username(self):
#         return self.user.username


class Message(models.Model):
    contenu = models.TextField()
    expediteur = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name="messages_envoyes"
    )
    groupe_conversation = models.ForeignKey(
        GroupeConversation, on_delete=models.CASCADE, related_name="messages"
    )
    date_creation = models.DateTimeField(auto_now_add=True)
