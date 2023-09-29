from django.urls import path, include
from .views import (
    AuthorList, GenreList, ConditionList, BookList, BookDetail, 
    ExpressInterestView, ChooseInterestedUserView, BookInterestsView, AllBooksInterestsView, register, user_login, user_logout, CurrentUserViewSet
)
from rest_framework.routers import DefaultRouter

from rest_framework.routers import DefaultRouter
router = DefaultRouter()
router.register(r'current', CurrentUserViewSet, basename='currentuser')

urlpatterns = [
    path("authors/", AuthorList.as_view(), name="author-list"),
    path("genres/", GenreList.as_view(), name="genre-list"),
    path("conditions/", ConditionList.as_view(), name="condition-list"),
    path('books/', BookList.as_view(), name='book-list'),
    path('books/<int:pk>/', BookDetail.as_view(), name='book-detail'),
    path('register/', register, name='register'),
    path('login/', user_login, name='login'),
    path('logout/', user_logout, name='logout'),
    path('express-interest/', ExpressInterestView.as_view(), name='express-interest'),
    path('book-interests/<int:pk>/', BookInterestsView.as_view(), name='book-interests'),
    path('all-book-interests/', AllBooksInterestsView.as_view(), name='all-book-interests'),
    path('choose-interested-user/', ChooseInterestedUserView.as_view(), name='choose-interested-user'),
    path("", include(router.urls))
]
