from rest_framework import serializers
from .models import Author, Genre, Condition, Book, BookInterest
from django.contrib.auth.models import User

class AuthorSerializer(serializers.ModelSerializer):
  class Meta:
    model = Author
    fields = "__all__"

class GenreSerializer(serializers.ModelSerializer):
  class Meta:
    model = Genre
    fields = "__all__"

class ConditionSerializer(serializers.ModelSerializer):
  class Meta:
    model = Condition
    fields = "__all__"

class BookSerializer(serializers.ModelSerializer):
    owner = serializers.ReadOnlyField(source='owner.username')  

    class Meta:
        model = Book
        fields = "__all__"
        read_only_fields = ("id", "created_at", "updated_at")

class ChooseInterestedSerializer(serializers.ModelSerializer):
    owner = serializers.ReadOnlyField(source='owner.username')
    interested_users = serializers.SerializerMethodField()

    class Meta:
        model = Book
        fields = ("id", "owner", "status", "interested_users")

    def get_interested_users(self, obj):
        # Query the BookInterest model to get interested users for the given book
        interests = BookInterest.objects.filter(book=obj)

        if interests.exists():
            # Get the interested users' usernames as a list
            interested_users = [interest.interested_user.username for interest in interests]
            return interested_users
        else:
            return None


class RegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()

    class Meta:
        model = User
        fields = ('username', 'email', 'password')
        extra_kwargs = {'password': {'write_only': True}}



class BookExpressInterestSerializer(serializers.ModelSerializer):
    status = serializers.ReadOnlyField(source='book.status')

    class Meta:
        model = BookInterest
        fields = ("book", "timestamp", "status")


class BookInterestSerializer(serializers.ModelSerializer):
    # Define a read-only status field
    status = serializers.ReadOnlyField(source='book.status')

    class Meta:
        model = BookInterest
        fields = ("interested_user", "book", "timestamp", "status")


# serializers.py
from django.contrib.auth.models import User
from rest_framework import serializers

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'first_name', 'last_name')
