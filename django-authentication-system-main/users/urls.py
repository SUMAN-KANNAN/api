from django.urls import path
from . import views


from .views import (
    LogIn,
    success,
    user_logout,
    SignUp
)

urlpatterns = [
    path("", LogIn.as_view(), name="login"),
    path("success/", success, name="success"),
    path("logout/", user_logout, name="logout"),
    path("signup/", SignUp.as_view(), name="signup"),
     path('generate_permanent_token/', views.generate_permanent_token, name='generate_permanent_token'),
    path('receive_data/', views.receive_data, name='receive_data'),
    path("suman/", views.suman, name="suman")
    # Add other URL patterns as needed
    
]

