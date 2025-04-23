import re
from django.shortcuts import render;
from django.http import HttpResponse, JsonResponse
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
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
import json
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .utils import api_response


# Create your views here.
@login_required
def Home(request):
    return HttpResponse("Hello, World!")


@login_required
def Dashboard(request):
    return render(request, 'dashboard.html')

@csrf_exempt  # Only use this for testing! Remove for production
def RegisterView(request):
    if request.method == 'POST':
        # Debug output
        print("POST data received:", request.POST)
        print("Files received:", request.FILES)
        
        first_name = request.POST.get('first_name') or ''
        last_name = request.POST.get('last_name') or ''
        email = request.POST.get('email') or ''
        username = request.POST.get('username') or ''
        password = request.POST.get('password') or ''
        confirm_password = request.POST.get('confirm_password') or ''

        user_data_has_error = False

        # Now check if any required fields are empty
        if not first_name:
            messages.error(request, 'First name is required')
            user_data_has_error = True
        elif len(first_name) < 3:
            messages.error(request, 'First name must be at least 3 characters')
            user_data_has_error = True

        if not last_name:
            messages.error(request, 'Last name is required')
            user_data_has_error = True
        elif len(last_name) < 3:
            messages.error(request, 'Last name must be at least 3 characters')
            user_data_has_error = True

        if not username:
            messages.error(request, 'Username is required')
            user_data_has_error = True
        elif len(username) < 3:
            messages.error(request, 'Username must be at least 3 characters')
            user_data_has_error = True

        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists')
            user_data_has_error = True;
        
        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists')
            user_data_has_error = True;
        
        
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            messages.error(request, 'Please enter a valid email address')
            user_data_has_error = True;
    

        if password != confirm_password:
            messages.error(request, 'Passwords do not match')
            user_data_has_error = True;
        
        if len(password) < 8:
            messages.error(request, 'Password must be at least 8 characters')
            user_data_has_error = True;

        if user_data_has_error:
            return redirect('register')
        
        else:
            new_user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                is_active=True,
                is_staff=False,
                is_superuser=False,
            )
            new_user.save()
            messages.success(request, 'Account created successfully. Please login to continue.')
            return redirect('login')
    
    # For GET requests, just render the registration page
    return render(request, 'register.html')
            
    
@csrf_exempt
def LoginView(request):
    if request.method == 'POST':
        print("LOGIN POST data received:", request.POST)
        print("LOGIN GET data received:", request.GET)
        
        # Get login credential (could be username or email)
        login_credential = request.POST.get('username') or request.GET.get('username')
        password = request.POST.get('password') or request.GET.get('password')
        
        print(f"Attempting to authenticate with credential: '{login_credential}'")
        
        # Determine if the input is an email or username
        is_email = '@' in login_credential if login_credential else False
        
        username = None
        if is_email:
            # If it's an email, find the associated username
            try:
                user = User.objects.get(email=login_credential)
                username = user.username
                print(f"Found username '{username}' for email '{login_credential}'")
            except User.DoesNotExist:
                print(f"No user found with email: {login_credential}")
                messages.error(request, 'No account associated with this email')
                return render(request, 'login.html')
        else:
            # It's a username
            username = login_credential
            
        # Try authentication with the username
        user = authenticate(request, username=username, password=password)
        
        print(f"Authentication result: {user}")
        
        if user is not None:
            print(f"Login successful for user: {username}")
            login(request, user)
            return redirect('dashboard')
        else:
            print(f"Login failed for user: {username}")
            # Check if user exists but password is wrong
            if User.objects.filter(username=username).exists():
                messages.error(request, 'Incorrect password')
            else:
                messages.error(request, 'Username does not exist')
    
    return render(request, 'login.html')

def LogoutView(request):
    logout(request)  # This uses the imported logout function from django.contrib.auth
    messages.success(request, "You have been successfully logged out.")
    return redirect('login')

def ForgotPasswordView(request):
    return render(request, 'forgot_password.html')

@csrf_exempt
def api_register(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            first_name = data.get('first_name')
            last_name = data.get('last_name')
            email = data.get('email')
            username = data.get('username')
            password = data.get('password')
            confirm_password = data.get('confirm_password')
            
            # Validation
            errors = []
            
            if len(first_name) < 3:
                errors.append('First name must be at least 3 characters')
            
            if len(last_name) < 3:
                errors.append('Last name must be at least 3 characters')
            
            if len(username) < 3:
                errors.append('Username must be at least 3 characters')
                
            if User.objects.filter(username=username).exists():
                errors.append('Username already exists')
            
            if User.objects.filter(email=email).exists():
                errors.append('Email already exists')
            
            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                errors.append('Please enter a valid email address')
            
            if password != confirm_password:
                errors.append('Passwords do not match')
            
            if len(password) < 8:
                errors.append('Password must be at least 8 characters')
            
            # Return errors if any
            if errors:
                return JsonResponse({
                    'success': False,
                    'errors': errors
                }, status=400)
            
            # If validation passes, create user
            new_user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                is_active=True,
                is_staff=False,
                is_superuser=False,
            )
            new_user.save()
            
            return JsonResponse({
                'success': True,
                'message': 'Account created successfully'
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': str(e)
            }, status=400)
    
    return JsonResponse({'error': 'Only POST method is allowed'}, status=405)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_data(request):
    # Example dashboard data
    return Response(
        api_response(
            message="Dashboard data retrieved successfully",
            data={
                'stats': {
                    'total_users': User.objects.count(),
                    'revenue': 9850,
                    'orders': 458,
                    'visitors': 9254
                },
                'recent_activities': [
                    {'user': 'John Doe', 'activity': 'Purchased Premium Plan', 'time': '10 min ago', 'status': 'completed'},
                    {'user': 'Jane Smith', 'activity': 'Updated profile information', 'time': '1 hour ago', 'status': 'completed'},
                    {'user': 'Robert Johnson', 'activity': 'Requested password reset', 'time': '3 hours ago', 'status': 'pending'},
                    {'user': 'Emily Davis', 'activity': 'Created new account', 'time': '5 hours ago', 'status': 'completed'},
                    {'user': 'Michael Wilson', 'activity': 'Submitted a support ticket', 'time': 'Yesterday', 'status': 'rejected'},
                ]
            }
        )
    )



