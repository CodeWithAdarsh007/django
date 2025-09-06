from django.shortcuts import render , redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
from django.core.mail import EmailMessage
from django.utils import timezone
from django.urls import reverse
from .models import *

@login_required
def Home(request):
    # print(request.user.is_authenticated)
    return render(request , 'index.html')


def SignupView(request):

    if request.method == "POST":
        full_name = request.POST.get('name')
        email = request.POST.get('email')
        college_name = request.POST.get('college')
        pass1 = request.POST.get('password1')
        pass2 = request.POST.get('password2')

        user_data_has_error = False 

        if User.objects.filter(username = email).exists():
            user_data_has_error = True
            messages.error(request , "Email already exists")

        if (len(pass1) < 5):
            user_data_has_error = True
            messages.error(request , "Password must be at least 5 characters.")

        if (pass1 != pass2):
            messages.error(request , "Password and Confirm Password must be same.")
            return render(request , 'signup.html')
        
        if user_data_has_error:
            return redirect('signup')
        else:
            new_user = User.objects.create_user(
                first_name = full_name,
                username = email,
                email = email,
                password = pass2, 
            )

            messages.success(request , "Account Created Successfully. Login now")
            return redirect('login')
        

    return render(request , 'signup.html')


def LoginView(request):

    if (request.method == "POST"):
        username = request.POST.get('email')
        password = request.POST.get('password')

        user = authenticate(request , username=username , password=password)

        if user is not None:
            login(request ,user)    #this login is what we have imported above
            return  redirect('home')
        else :
            messages.error(request , "Invalid login credentials")
            return redirect('login')

    return render(request , 'login.html')


def LogoutView(request):
    logout(request)
    return redirect('login')


def ForgotPassword(request):

    if request.method == "POST":
        email = request.POST.get('email')

        try:
            user = User.objects.get(email=email)

            new_password_reset = PasswordReset(user = user)
            new_password_reset.save()

            password_reset_url = reverse('reset_password' , kwargs={'reset_id' : new_password_reset.reset_id})

            full_password_reset_url = f"{request.scheme}://{request.get_host()}{password_reset_url}"

            email_body = f"Reset your password using this link below : \n\n\n{full_password_reset_url }"

            email_message = EmailMessage (
                "Reset your password",   # Subject
                email_body,
                settings.EMAIL_HOST_USER,    # email sender
                [email]     #email receiver
            )

            email_message.fail_silently = True
            email_message.send()

            return redirect('password_reset_sent' , reset_id = new_password_reset.reset_id)

        except User.DoesNotExist:
            messages.error(request , f"No user with this email found")
            return redirect('forgot_password')
        
    return render(request , 'forgot_password.html')


def PasswordResetSent(request , reset_id):

    if PasswordReset.objects.filter(reset_id = reset_id).exists():
        return render(request , 'password_reset_sent.html')
    else:
        messages.error(request , "Invalid reset id")
        return redirect('forgot_password')
    
    # return render(request , 'password_reset_sent.html')


def ResetPasswordView(request , reset_id): 

    try :
        password_reset_id = PasswordReset.objects.get(reset_id = reset_id)

        if request.method == "POST":
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')

            passwords_have_error = False

            if (password != confirm_password):
                passwords_have_error = True
                messages.error(request , "Password and Confirm Password must be same")
            
            if (len(password) < 5):
                passwords_have_error = True
                messages.error(request , "Password must be at least 5 characters.")

            expiration_time = password_reset_id.created_when + timezone.timedelta(minutes=10)

            if (timezone.now() > expiration_time):
                passwords_have_error = True
                messages.error(request , "Reset link has been expired.")

                password_reset_id.delete()

            if not passwords_have_error:
                user = password_reset_id.user
                user.set_password(password)
                user.save()

                password_reset_id.delete()   # delete the reset id for security purpose

                messages.success(request , "Password reset. Procced to login") 
                return redirect('login')
            
            else:
                return redirect('reset_password' , reset_id = reset_id)

    except PasswordReset.DoesNotExist:
        messages.error(request , "Invalid reset id")
        return redirect(request , 'forgot_password')
    
    return render(request , 'reset_password.html' , {'reset_id' : reset_id})

# print(User.objects.all())

def ChatsView(request):
    return render(request , 'chats.html')