web: python manage.py migrate --noinput && python manage.py collectstatic --noinput && gunicorn pocketops.wsgi:application --bind 0.0.0.0:${PORT:-8000} --workers 2 --timeout 60

