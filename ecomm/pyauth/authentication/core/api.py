# core/api.py
from rest_framework import status, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
import json
from .utils import api_response

# Serializers
from rest_framework import serializers

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name']
        
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'confirm_password', 'first_name', 'last_name']
        
    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        if len(data['password']) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters.")
        return data
    
    def create(self, validated_data):
        validated_data.pop('confirm_password')
        user = User.objects.create_user(**validated_data)
        return user

# API views
@api_view(['POST'])
@permission_classes([AllowAny])
def register_api(request):
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        refresh = RefreshToken.for_user(user)
        
        # Ensure we return tokens in a consistent format
        return Response(
            api_response(
                message="Registration successful",
                data={
                    'user': UserSerializer(user).data,
                    'tokens': {
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                    }
                }
            ),
            status=status.HTTP_201_CREATED
        )
    
    return Response(
        api_response(
            message="Registration failed",
            errors=serializer.errors,
            success=False
        ), 
        status=status.HTTP_400_BAD_REQUEST
    )

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def login_api(request):
    print("LOGIN API REACHED")
    print("Request method:", request.method)
    print("Request data:", request.data)
    username = request.data.get('username')
    password = request.data.get('password')
    
    # Validation
    if not username or not password:
        return Response(
            api_response(
                message="Username and password are required",
                errors={"credentials": "Both username and password are required"},
                success=False
            ), 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Support email login
    if '@' in username:
        try:
            user = User.objects.get(email=username)
            username = user.username
        except User.DoesNotExist:
            return Response(
                api_response(
                    message="No account found with this email",
                    errors={"email": "No account associated with this email"},
                    success=False
                ), 
                status=status.HTTP_401_UNAUTHORIZED
            )
    
    user = authenticate(username=username, password=password)
    
    if user is not None:
        refresh = RefreshToken.for_user(user)
        
        return Response(
            api_response(
                message="Login successful",
                data={
                    'user': UserSerializer(user).data,
                    'tokens': {
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                    }
                }
            ),
            status=status.HTTP_200_OK
        )
        
    return Response(
        api_response(
            message="Invalid credentials",
            errors={"credentials": "Username or password is incorrect"},
            success=False
        ), 
        status=status.HTTP_401_UNAUTHORIZED
    )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile(request):
    user = request.user
    serializer = UserSerializer(user)
    
    return Response(
        api_response(
            message="User profile retrieved successfully",
            data=serializer.data
        )
    )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_data(request):
    # Example dashboard data
    return Response({
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
    })

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_me(request):
    """Return detailed user information including permissions"""
    user = request.user
    
    # Get user permissions
    permissions = []
    if user.is_superuser:
        permissions.append('admin')
    if user.is_staff:
        permissions.append('staff')
    
    # Get user groups
    groups = [group.name for group in user.groups.all()]
    
    # Last login timestamp
    last_login = user.last_login.isoformat() if user.last_login else None
    
    return Response(
        api_response(
            data={
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'full_name': f"{user.first_name} {user.last_name}".strip(),
                'date_joined': user.date_joined.isoformat(),
                'last_login': last_login,
                'is_active': user.is_active,
                'permissions': permissions,
                'groups': groups
            },
            message="User profile retrieved successfully"
        )
    )

# Add this test endpoint
@api_view(['GET'])
@permission_classes([AllowAny])
def test_api(request):
    return Response({"message": "API is working!"})