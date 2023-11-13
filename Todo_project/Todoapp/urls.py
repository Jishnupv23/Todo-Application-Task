from django.urls import path
from .views import Login,Signup,VerifyOTP,AddProfile,ForgetPassword,OTPVerification,ChangePassword,ResendOTP,AddTask,DeleteTask,ViewTasks

urlpatterns = [
    path('auth/login/',Login.as_view(),name='login'),
    path('auth/signup/',Signup.as_view(),name='signup'),
    path('auth/verifyotp/',VerifyOTP.as_view(),name='verify_otp'),
    path('auth/add-profile/',AddProfile.as_view(),name='add_profile'),
    path('auth/forget-password/',ForgetPassword.as_view(),name='forget_password'),
    path('auth/otp-verify/',OTPVerification.as_view(),name='otp_verify'),
    path('auth/change-password/',ChangePassword.as_view(),name='change_password'),
    path('auth/resendotp/',ResendOTP.as_view(),name='resend_otp'),
    path('task/addtask/',AddTask.as_view(), name='add_task'),
    path('task/deletetask/<int:task_id>/',DeleteTask.as_view(),name='delete_task'),
    path('task/view-task/',ViewTasks.as_view(),name='view_tasks'),
    
]