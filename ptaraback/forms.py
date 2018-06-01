from .models import ptaraUsers
from django import forms

class UserForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = ptaraUsers
        fields = '__all__'