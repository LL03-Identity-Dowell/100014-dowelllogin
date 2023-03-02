from django.utils.translation import gettext_lazy as _
from django import forms

ROLE_CHOICES = (
    ('', 'Choose...'),
    # ("Company_Lead", "Company Lead"),
    # ("Org_Lead", "Orgnisation Lead"),
    # ("Dept_Lead", "Department Lead"),
    # ("Client_Admin", "Client Admin"),
    # ("Proj_Lead", "Project Lead"),
    # ("Team_Member", "Team Member"),
    # ("Hr", "Hr"),
    ("User", "User"),
)
PHONE_CHOICES = (

    ("+91", "+91"),
    ("+88", "+88"),
    ("+92", "+92"),
)
class UserRegisterForm(forms.Form):
    username=forms.CharField(label=_('Username'), widget=forms.TextInput(attrs={'placeholder': _('Username')}))
    password1=forms.CharField(label=_('Password'),min_length=8,widget=forms.PasswordInput(attrs={'placeholder': _('Password')}))
    password2=forms.CharField(min_length=8,label=_('Confirm Password'), widget=forms.PasswordInput( attrs={'placeholder': _('Password')}))
    first_name=forms.CharField(label=_('First Name'), widget=forms.TextInput(attrs={'placeholder': _('First Name')}))
    last_name=forms.CharField(label=_('Last Name'),required=False,widget=forms.TextInput(attrs={'placeholder': _('Last Name')}))
    email=forms.EmailField(label=_('Email'),widget=forms.TextInput(attrs={'placeholder': _('Email')}))
    role=forms.ChoiceField(label=_('Your Designation'),choices=ROLE_CHOICES)
    teamcode=forms.IntegerField(required=False,label=_('Team Code'),widget=forms.NumberInput(attrs={'placeholder': _('Team Code')}))
    phonecode=forms.ChoiceField(choices=PHONE_CHOICES,label=_('Code'))
    phone=forms.IntegerField(label=_('Phone'),required=False,widget=forms.NumberInput(attrs={'placeholder': _('Phone')}))


