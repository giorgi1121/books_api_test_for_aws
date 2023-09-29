from django.db import models
from django.contrib.auth.models import User
# Create your models here.


class Author(models.Model):
  name = models.CharField(max_length=100)

  def __str__(self):
    return self.name
  
class Genre(models.Model):
  name = models.CharField(max_length=100)

  def __str__(self):
    return self.name
  
class Condition(models.Model):
  name = models.CharField(max_length=100) 

  def __str__(self):
    return self.name
  
class Book(models.Model):
    STATUS_CHOICES = [
        ('available', 'Available'),
        ('requested', 'Requested'),
        ('borrowed', 'Borrowed'),
    ]

    title = models.CharField(max_length=255)
    author = models.ForeignKey(Author, on_delete=models.CASCADE)
    genre = models.ManyToManyField(Genre)
    condition = models.ForeignKey(Condition, on_delete=models.CASCADE)
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='available')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    pickup_location = models.CharField(max_length=255)
    borrowed_to = models.ForeignKey(User, related_name='borrowed_books', null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
       ordering = ["id"]

    def __str__(self):
      return self.title
    

class BookInterest(models.Model):
    interested_user = models.ForeignKey(User, on_delete=models.CASCADE)
    book = models.ForeignKey(Book, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
       ordering = ["id"]

    def __str__(self):
      return self.interested_user