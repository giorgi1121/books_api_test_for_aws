from django.shortcuts import render

# Create your views here.
from rest_framework import generics
from .models import Author, Genre, Condition, Book
from django.contrib.auth.models import User
from .serializers import AuthorSerializer, GenreSerializer, ConditionSerializer, BookSerializer
from rest_framework.permissions import IsAuthenticated, IsAuthenticatedOrReadOnly, AllowAny
from rest_framework.generics import RetrieveUpdateDestroyAPIView
from rest_framework.exceptions import PermissionDenied
from rest_framework.decorators import action
from rest_framework import viewsets
from .filters import BookFilter

class AuthorList(generics.ListCreateAPIView):
  queryset = Author.objects.all()
  serializer_class = AuthorSerializer
  permission_classes = [IsAuthenticated]

class GenreList(generics.ListCreateAPIView):
  queryset = Genre.objects.all()
  serializer_class = GenreSerializer
  permission_classes = [IsAuthenticated]

class ConditionList(generics.ListCreateAPIView):
  queryset = Condition.objects.all()
  serializer_class = ConditionSerializer
  permission_classes = [IsAuthenticated]

class BookList(generics.ListCreateAPIView):
    serializer_class = BookSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]
    queryset = Book.objects.all()
    filterset_class = BookFilter
    
    def perform_create(self, serializer):
        # Set the owner of the book to the currently authenticated user
        serializer.save(owner=self.request.user)
    


class BookDetail(RetrieveUpdateDestroyAPIView):
    queryset = Book.objects.all()
    serializer_class = BookSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        # Get the book instance
        book = super().get_object()

        # Check if the current user is the owner of the book
        if self.request.user != book.owner:
            raise PermissionDenied('You do not have permission to access this book.')

        return book
    





# REGISTRATION/AUTHORIZATION


from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import Book
from .serializers import BookSerializer, RegistrationSerializer

@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    serializer = RegistrationSerializer(data=request.data)
    if serializer.is_valid():
        username = serializer.validated_data['username']
        email = serializer.validated_data['email']  # Get email from serializer
        password = serializer.validated_data['password']

        if User.objects.filter(username=username).exists():
            return Response({'message': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if email is already in use
        if User.objects.filter(email=email).exists():
            return Response({'message': 'Email already in use'}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(username=username, email=email, password=password)
        return Response({'message': 'Registration successful'}, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def user_login(request):
    username = request.data.get('username')
    password = request.data.get('password')

    user = authenticate(request, username=username, password=password)

    if user is not None:
        login(request, user)
        return Response({'message': 'Login successful'}, status=status.HTTP_200_OK)
    else:
        return Response({'message': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def user_logout(request):
    logout(request)
    return Response({'message': 'Logged out'}, status=status.HTTP_200_OK)


# views for expressing interest


from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from .models import BookInterest
from .serializers import BookInterestSerializer, BookExpressInterestSerializer

from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import BookInterest, Book

class ExpressInterestView(generics.ListCreateAPIView):
    serializer_class = BookExpressInterestSerializer
    permission_classes = [IsAuthenticated]
    queryset = BookInterest.objects.all()

    def create(self, request, *args, **kwargs):
        # Get the book ID from the request data
        book_id = request.data.get('book')

        try:
            book = Book.objects.get(pk=book_id)
        except Book.DoesNotExist:
            return Response({'message': f'Book with ID {book_id} does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the book is available for expressing interest
        if book.status == 'borrowed':
            return Response({'message': 'This book is not available for expressing interest.'}, status=status.HTTP_400_BAD_REQUEST)

        # Automatically set the interested_user to the currently authenticated user
        serializer = self.get_serializer(data={'book': book_id})
        serializer.is_valid(raise_exception=True)

        interest_exists = BookInterest.objects.filter(
            interested_user=self.request.user, book_id=book_id
        ).exists()

        if interest_exists:
            return Response({'message': 'User is already interested in this book.'}, status=status.HTTP_400_BAD_REQUEST)

        serializer.save(interested_user=self.request.user)

        # Update the book status to "Requested"
        book.status = 'requested'
        book.save()

        return Response({'message': 'Expressed interest in the book successfully.'}, status=status.HTTP_201_CREATED)



class BookInterestsView(generics.ListAPIView):
    serializer_class = BookInterestSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        book_id = self.kwargs['pk']
        return BookInterest.objects.filter(book_id=book_id)
    

class AllBooksInterestsView(generics.ListAPIView):
    serializer_class = BookInterestSerializer
    permission_classes = [IsAuthenticated]
    queryset = BookInterest.objects.all()
    


from rest_framework import status, serializers
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework import generics
from django.db.models import F, Value
from django.db.models.functions import Concat
from django.db.models import CharField
from django.contrib.auth.models import User

class ChooseInterestedUserView(generics.ListCreateAPIView):
    serializer_class = BookInterestSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Get the current user
        user = self.request.user

        # Annotate the BookInterest queryset with related Book data
        queryset = BookInterest.objects.annotate(
            book_title=Concat(
                F("book__title"), Value(" - "), F("book__author__name"), output_field=CharField()
            )
        )

        # Filter the queryset to include only BookInterests related to books where the user is the owner
        queryset = queryset.filter(book__owner=user)

        return queryset

    def perform_create(self, serializer):
        # Get the current user
        user = self.request.user

        # Get the book ID from the POST data
        book_id = self.request.data.get("book")

        # Get the interested user ID from the POST data
        interested_user_id = self.request.data.get("interested_user")

        # Check if the user is interested in the specified book
        is_interested = BookInterest.objects.filter(
            interested_user=interested_user_id, book_id=book_id
        ).exists()

        if not is_interested:
            # If the user is not already interested, raise a validation error
            raise serializers.ValidationError({'message': 'User is not interested in this book.'})

        # Check if the specified book belongs to the current user
        is_owner = Book.objects.filter(owner=user, id=book_id).exists()

        if not is_owner:
            # If the user does not own the book, raise a validation error
            raise serializers.ValidationError({'message': 'You do not own this book.'})

        # Update the book's status to "Borrowed" and set the borrowed_to field
        book = Book.objects.get(id=book_id)
        book.status = 'borrowed'
        book.borrowed_to_id = interested_user_id
        book.save()

        # Create a new BookInterest record
        serializer.save(interested_user_id=interested_user_id, book_id=book_id)

        return Response({'message': 'Book has been borrowed by the selected user'}, status=status.HTTP_201_CREATED)



   
    
    
    

    """ def create(self, request, *args, **kwargs):
        book_id = self.kwargs['pk']
        try:
            book = Book.objects.get(pk=book_id)
        except Book.DoesNotExist:
            return Response({'message': 'Book not found'}, status=status.HTTP_404_NOT_FOUND)

        # Check if the user making the request is the owner of the book
        if request.user != book.owner:
            return Response({'message': 'You do not have permission to choose an interested user for this book.'}, status=status.HTTP_403_FORBIDDEN)

        # Ensure 'interested_user_id' is present in the request data
        interested_user_id = request.data.get('interested_user')
        if interested_user_id is None:
            return Response({'message': 'interested_user_id is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            interested_user = User.objects.get(pk=interested_user_id)
        except User.DoesNotExist:
            return Response({'message': f'User with ID {interested_user_id} does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        # Update the book's status to "Borrowed" and set the borrowed_by field
        book.status = 'borrowed'
        book.borrowed_by = interested_user
        book.save()

        # Create a BookInterest record for the chosen user
        BookInterest.objects.create(interested_user=interested_user, book=book)

        return Response({'message': 'Book has been borrowed by the selected user'}, status=status.HTTP_201_CREATED) """


# views.py
from django.contrib.auth.models import User
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from .serializers import UserSerializer

class CurrentUserViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Return the current user.
        return User.objects.filter(pk=self.request.user.pk)






""" # myapp/views.py

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import UserSerializer
from rest_framework.permissions import AllowAny

class UserRegistrationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({"message": "User registered successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

from django.contrib.auth import login
from rest_framework import permissions
from rest_framework.authtoken.serializers import AuthTokenSerializer
from knox.views import LoginView as KnowLoginView

class LoginAPI(KnowLoginView):
   permission_classes = (permissions.AllowAny,)

   def post(self, request, format=None):
      serializer = AuthTokenSerializer(data=request.data)
      serializer.is_valid(raise_exception=True)
      user = serializer.validated_data["user"]
      login(request, user)
      return super(LoginAPI, self).post(request, format=None)
 """













""" from django.contrib.auth import login, authenticate
from rest_framework.authtoken.serializers import AuthTokenSerializer
from knox.views import LoginView as KnoxLoginView
from .serializers import UserLoginSerializer """




""" class UserLoginView(APIView):
    def get(self, request):
        response_data = {
            "message": "Provide login credentials in a POST request.",
            "example_request": {
                "method": "POST",
                "url": "/login/",
                "data": {
                    "username": "your_username",
                    "password": "your_password"
                }
            }
        }
        return Response(response_data, status=status.HTTP_200_OK) """
""" 
class UserLoginView(APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)

        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']

            # Authenticate the user
            user = authenticate(request, username=username, password=password)

            if user is not None:
                # Login the user
                login(request, user)
                return Response({"message": "Login successful"}, status=status.HTTP_200_OK)
            else:
                return Response({"message": "Invalid login credentials"}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST) """