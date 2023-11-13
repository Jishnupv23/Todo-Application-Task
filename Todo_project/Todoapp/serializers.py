from rest_framework import serializers
from .models import Task


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=4)


class SignupSerializer(serializers.Serializer):
    email = serializers.EmailField()

class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=4)

class AddProfileSerializer(serializers.Serializer):
    fname = serializers.CharField(max_length=250)
    lname = serializers.CharField(max_length=250)
    dob = serializers.DateField(required=False)
    profile_pic = serializers.ImageField(required=False)

class ForgetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

class OTPVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=4)

class ChangePasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(max_length=100)

class ResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

class AddTaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = ['id', 'title', 'description', 'completed']

    def create(self, validated_data):
        user = self.context['user']
        task = Task.objects.create(user=user, **validated_data)
        return task

class DeleteTaskSerializer(serializers.Serializer):
    task_id = serializers.IntegerField()


class TaskListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = '__all__'