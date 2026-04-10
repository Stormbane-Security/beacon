"""Minimal Django app with DEBUG=True for fingerprinting tests."""
import os, sys, django
from django.conf import settings

settings.configure(
    DEBUG=True,
    SECRET_KEY="insecure-test-key",
    ROOT_URLCONF=__name__,
    ALLOWED_HOSTS=["*"],
    INSTALLED_APPS=["django.contrib.contenttypes", "django.contrib.auth"],
)
django.setup()

from django.http import HttpResponse
from django.urls import path

def index(request):
    return HttpResponse(
        "<html><head><title>Django Debug</title></head>"
        "<body><h1>Welcome to Django</h1></body></html>",
        content_type="text/html",
    )

urlpatterns = [path("", index)]

if __name__ == "__main__":
    from django.core.management import execute_from_command_line
    sys.argv = ["manage.py", "runserver", "0.0.0.0:8000"]
    execute_from_command_line(sys.argv)
