web: waitress-serve --host=0.0.0.0 --port=${PORT:-51222} --threads=8 --trusted-proxy='*' --trusted-proxy-count=1 --trusted-proxy-headers='x-forwarded-for x-forwarded-proto' login:app
