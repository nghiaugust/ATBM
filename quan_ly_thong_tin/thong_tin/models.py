from django.db import models
from django.contrib.auth.models import User

class ThongTin(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # Liên kết với User
    tieu_de = models.CharField(max_length=255)  
    du_lieu = models.TextField()  