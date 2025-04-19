from django.shortcuts import render;
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
from django.core.mail import EmailMessage
from django.utils import timezone
from django.urls import reverse
from .models import *


# Create your views here.
def Home(request):
    return HttpResponse("Hello, World!")

def RegisterView(request):
    return render(request, 'register.html')

def LoginView(request):
    return render(request, 'login.html')

def LogoutView(request):
    return redirect('login')

def ForgotPasswordView(request):
    return render(request, 'forgot_password.html')



