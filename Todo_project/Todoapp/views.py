from rest_framework.views import APIView
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings
from django.utils.crypto import get_random_string
from .models import Task
from .serializers import LoginSerializer,SignupSerializer,VerifyOTPSerializer,AddProfileSerializer,ForgetPasswordSerializer,OTPVerificationSerializer,ChangePasswordSerializer,ResendOTPSerializer,AddTaskSerializer,DeleteTaskSerializer,TaskListSerializer
    
#login view
class Login(APIView):

    def post(self,request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']

            user = User.objects.get(username=email)
            if user.check_password(otp):
                token, created = Token.objects.get_or_create(user=user)
                return Response({'access_token':token.key,'refresh_token':token.key})
            else:
                return Response({'message':'Invalid OTP'},status=400)
        else:
            return Response(serializer.errors,status=400)

#signup view
class Signup(APIView):

    def post(self,request,*args,**kwargs):
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = get_random_string(length=4,allowed_chars='1234567890')

            send_mail(
                'Todoapp OTP verification',
                f'OTP for Todoapp is:{otp}',
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )

            user = User.objects.create_user(email,otp)
            return Response({'message':'User created'})
        else:
            return Response(serializer.errors,status=400)




#verify_otp view    
class VerifyOTP(APIView):

    def post(self,request,*args,**kwargs):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']

            user = User.objects.get(username=email)
            if user.check_password(otp):
                token, created = Token.objects.get_or_create(user=user)
                return Response({'access_token': token.key, 'refresh_token': token.key})
            else:
                return Response({'message':'Invalid OTP'},status=400)
        else:
            return Response(serializer.errors,status=400)
    


#add_profile view
class AddProfile(APIView):

    def post(self,request,*args,**kwargs):
        user = request.user
        serializer = AddProfileSerializer(data=request.data)
        if serializer.is_valid():
            fname = serializer.validated_data.get('fname')
            lname = serializer.validated_data.get('lname')
            dob = serializer.validated_data.get('dob')
            profile_pic = serializer.validated_data.get('profile_pic')

            user.first_name = fname
            user.last_name = lname
            if dob:
                user.dob = dob
            if profile_pic:
                user.profile_pic = profile_pic
            user.save()

            return Response({'message':'Profile added successfully'})
        else:
            return Response(serializer.errors,status=400)



#forget_password view
class ForgetPassword(APIView):

    def post(self,request,*args,**kwargs):
        serializer = ForgetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = get_random_string(length=4,allowed_chars='1234567890')

            send_mail(
                'Todoapp-Password Reset',
                f'OTP for Todoapp password reset is:{otp}',
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )

            user = User.objects.get(username=email)
            user.set_password(otp)
            user.save()

            return Response({'message':'Password reset email sent'})
        else:
            return Response(serializer.errors,status=400)



#otp_verify view
class OTPVerification(APIView):

    def post(self,request,*args,**kwargs):
        serializer = OTPVerificationSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']

            user = User.objects.get(username=email)
            if user.check_password(otp):
                return Response({'message':'OTP verified successfully'})
            else:
                return Response({'message':'Invalid OTP'},status=400)
        else:
            return Response(serializer.errors,status=400)


#change_password view
class ChangePassword(APIView):

    def post(self,request,*args,**kwargs):
        user = request.user
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            new_password = serializer.validated_data['new_password']

            user.set_password(new_password)
            user.save()
            return Response({'message':'Password changed successfully'})
        else:
            return Response(serializer.errors,status=400)



#resend_otp view
class ResendOTP(APIView):

    def post(self,request,*args,**kwargs):
        serializer = ResendOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            new_otp = get_random_string(length=4, allowed_chars='1234567890')

            send_mail(
                'Todoapp-Password Reset',
                f'New OTP for Todoapp password reset is:{new_otp}',
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )

            user = User.objects.get(username=email)
            user.set_password(new_otp)
            user.save()

            return Response({'message':'New OTP sent'})
        else:
            return Response(serializer.errors,status=400)



#add_task view
class AddTask(APIView):

    def post(self,request,*args,**kwargs):
        user = request.user
        serializer = AddTaskSerializer(data=request.data, context={'user': user})
        if serializer.is_valid():
            serializer.save()
            return Response({'message':'Task added successfully'})
        else:
            return Response(serializer.errors,status=400)



#delete_task view
class DeleteTask(APIView):

    def put(self,request,task_id,*args,**kwargs):
        user = request.user
        serializer = DeleteTaskSerializer(data={'task_id': task_id})
        if not serializer.is_valid():
            return Response(serializer.errors, status=400)
        
        task_id = serializer.validated_data['task_id']

        try:
            task = Task.objects.get(id=task_id, user=user)
        except Task.DoesNotExist:
            return Response({'message':'Task not found'},status=404)

        task.delete()
        return Response({'message':'Task deleted successfully'})


#view task view
class ViewTasks(APIView):

    def get(self,request,*args,**kwargs):
        user = request.user
        tasks = Task.objects.filter(user=user)
        serializer = TaskListSerializer(tasks, many=True)
        return Response(serializer.data)




