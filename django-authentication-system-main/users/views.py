from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.views import LoginView
from django.shortcuts import render, redirect
from django.contrib import messages
from django.urls import reverse_lazy
from django.views.generic import CreateView


class LogIn(LoginView):
    template_name = 'index.html'

    def post(self, request, *args, **kwargs):
        username = request.POST.get('username')
        password = request.POST.get('password')
        rememberme = request.POST.get('rememberme')

        user_obj = User.objects.filter(username=username).first()
        if user_obj is None:
            messages.success(request=request, message="Foydalanuvchi topilmadi!!!")
            return redirect('login')
        user = authenticate(username=username, password=password)
        if user is None:
            messages.success(request=request, message="Noto'g'ri parol kiritilgan")
            return redirect('login')
        login(request=request, user=user)
        if not rememberme:
            self.request.session.set_expiry(0)
            self.request.session.modified = True
        messages.success(request=request, message="Success")
        return redirect('success')


class SignUp(CreateView):
    model = User
    fields = "__all__"
    template_name = 'register.html'
    success_url = reverse_lazy('login')

    def post(self, request, *args, **kwargs):
        try:
            password1 = request.POST.get('password1')
            password2 = request.POST.get('password2')
            username = request.POST.get('username')
            email = request.POST.get('email')
            first_name = request.POST.get('firstname')
            last_name = request.POST.get('lastname')

            if password1 != password2:
                messages.success(request, 'Entered Wrong password')
                return redirect('signup')

            if User.objects.filter(username=username).first():
                messages.success(request, "Entered user id wrong")
                return redirect('signup')

            if User.objects.filter(email=email).first():
                messages.success(request, "make  a email")
                return redirect('signup')

            user_obj = User.objects.create(username=username, email=email, first_name=first_name, last_name=last_name)
            user_obj.set_password(raw_password=password1)
            user_obj.save()
            return redirect('login')
        except Exception as e:
            messages.error(request, f"Xatolik {e}")
            return redirect('signup')


def success(request):
    return render(request=request, template_name='success.html', context={})


def user_logout(request):
    logout(request)
    return redirect(to='login')

from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import UserProfile

def generate_permanent_token(request):
    user_profile, created = UserProfile.objects.get_or_create(user=request.user)
    token = user_profile.token  # Corrected attribute name to 'token'

    if not token:
        # Generate a new permanent token
        token = default_token_generator.make_token(request.user)
        user_profile.token = token  # Corrected attribute name to 'token'
        user_profile.save()
        print(f"Generated and saved permanent token: {token}")
    else:
        print(f"Using existing token: {token}")

    return render(request, 'success.html', {'permanent_token': token})



@api_view(['POST'])
def receive_data(request):
    if request.method == 'POST':
        # Authenticate the user using the permanent token
        token = request.META.get('HTTP_AUTHORIZATION')
        token ="bwoaug-28d82ed4c6e483ee9b5f4473f45990fe"
        user_profile = UserProfile.objects.filter(token=token).first()

        if not user_profile:
            return Response({'message': 'Unauthorized'}, status=401)

        # Handle the data sent from Raspberry Pi here
        # You can use a serializer to validate and save the data
        # For this example, we'll just print the received data
        data = request.data
        print(data)
        return Response({'message': 'Data received successfully'}, status=200)


def suman (request):
    user_profile = UserProfile.objects.get(user=request.user)
    if user_profile.permanent_token:
            # The token has been generated, and you can access it with user_profile.permanent_token
        print(f"Permanent Token: {user_profile.permanent_token}")
    else:
            # The token hasn't been generated yet for this user
        print("No permanent token available.")

    return render(request, 'success.html', {'permanent_token': user_profile.permanent_token})


# from django.http import HttpResponse
# from rest_framework.response import Response

# def receive_data(request):
   
#         # Authenticate the user using the permanent token
#         # token = request.META.get('HTTP_AUTHORIZATION')
#         token ="bwoayg-f96784696c841d28c07e2d34cc963b27"
#         user_profile = UserProfile.objects.filter(token=token).first()
#         print("token authentication is successfull ", user_profile)

#         if not user_profile:
#             return Response({'message': 'Unauthorized'}, status=401)

#         # Handle the data sent from Raspberry Pi here
#         # You can use a serializer to validate and save the data
#         # For this example, we'll just print the received data
#         data = 0
#         print("////////////////////////////////////////",data)
#         content="<h1>welcome</h1>"
#         return HttpResponse (content)