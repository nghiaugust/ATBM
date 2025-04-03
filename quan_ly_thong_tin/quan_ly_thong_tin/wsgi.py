"""
WSGI config for quan_ly_thong_tin project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'quan_ly_thong_tin.settings')

application = get_wsgi_application()
try:
    from django.core.management import call_command
    call_command('migrate')
except Exception as e:
    print(f"Migration error: {e}")