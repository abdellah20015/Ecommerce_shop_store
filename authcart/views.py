from django.shortcuts import render, redirect, HttpResponse
from django.contrib.auth.models import User
from django.views.generic import View
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator


def signup(request):
    if request.method == "POST":
        email = request.POST['email']
        password = request.POST['pass1']
        confirm_password = request.POST['pass2']
        
        if password != confirm_password:
            messages.warning(request, "Les mots de passe ne correspondent pas.")
            return render(request, 'signup.html')
        
        if User.objects.filter(username=email).exists():
            messages.info(request, "Cet e-mail est déjà utilisé.")
            return render(request, 'signup.html')
        
        # Créer un nouvel utilisateur et le connecter directement
        user = User.objects.create_user(username=email, email=email, password=password)
        user.is_active = True
        user.save()
        
        # Connecter l'utilisateur directement
        user = authenticate(username=email, password=password)
        if user:
            login(request, user)
            messages.success(request, "Inscription réussie. Vous êtes maintenant connecté.")
            return redirect('/')
        
    return render(request, "signup.html")

def handlelogin(request):
    if request.method == "POST":
        email = request.POST['email']
        password = request.POST['pass1']
        user = authenticate(username=email, password=password)
        if user:
            login(request, user)
            return redirect('/')
        else:
            messages.error(request, "Identifiants invalides")
    return render(request, 'login.html')

def handlelogout(request):
    logout(request)
    messages.info(request, "Déconnexion réussie")
    return redirect('/auth/login')

class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception as identifier:
            user = None
        if user is not None and generate_token.check_token(user, token):
            user.is_active = True
            user.save()
            messages.info(request, "Compte activé avec succès")
            return redirect('/auth/login')
        return render(request, 'activatefail.html')

class RequestResetEmailView(View):
    def get(self, request):
        return render(request, 'request-reset-email.html')

    def post(self, request):
        email = request.POST['email']
        user = User.objects.filter(email=email)
        if user.exists():
            email_subject = '[Réinitialisez votre mot de passe]'
            message = render_to_string('reset-user-password.html', {
                'domain': '127.0.0.1:8000',
                'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
                'token': PasswordResetTokenGenerator().make_token(user[0])
            })
            messages.info(request, f"Nous vous avons envoyé un e-mail avec des instructions pour réinitialiser votre mot de passe {message} ")
            return render(request, 'request-reset-email.html')

class SetNewPasswordView(View):
    def get(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token
        }
        try:
            user_id = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                messages.warning(request, "Le lien de réinitialisation du mot de passe est invalide")
                return render(request, 'request-reset-email.html')
        except DjangoUnicodeDecodeError as identifier:
            pass
        return render(request, 'set-new-password.html', context)

def post(self, request):
    email = request.POST['email']
    user = User.objects.filter(email=email).first()
    if user:
        context = {
            'email': user.email,
            'domain': '127.0.0.1:8000',
            'site_name': 'YourSiteName',
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': default_token_generator.make_token(user),
            'protocol': 'http',
        }
        email_body = render_to_string('email_template_name.html', context)
        send_mail(
            'Reset Your Password',
            email_body,
            'from@example.com',
            [user.email],
            fail_silently=False,
        )
        messages.success(request, 'We have sent you an email with instructions on how to reset your password.')
    else:
        messages.error(request, 'No account found with this email')

    return render(request, 'request-reset-email.html')

