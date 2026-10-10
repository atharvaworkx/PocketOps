web: python manage.py migrate --noinput && python manage.py collectstatic --noinput && gunicorn pocketops.wsgi --bind 0.0.0.0:$PORT --workers 2 --timeout 60
