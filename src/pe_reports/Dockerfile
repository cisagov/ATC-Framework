# Use the Python 3.10.2 image as the base image

FROM python:3.10.2

# Install required tools
#RUN apt-get update && apt-get install -y curl build-essential

# Install Rust and Cargo
#RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

# Add Rust to PATH
#ENV PATH="/root/.cargo/bin:${PATH}"

# Install required tools
RUN apt-get update && apt-get install -y bash g++ gcc make redis redis-tools

# Create non-root user
RUN useradd -m -u 1001 atc_api

# Upgrade pip and certifi
RUN python3 -m pip install --upgrade pip && pip install --upgrade certifi



# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Create working directory with correct ownership
RUN mkdir /code && chown atc_api:atc_api /code
WORKDIR /code

# Install dependencies
COPY --chown=atc_api:atc_api ./pe_reports_django_project/pe_reports_django/requirements.txt /code/
RUN pip install --no-cache-dir -r requirements.txt
# Copy the project code
COPY --chown=atc_api:atc_api pe_reports_django_project /code

# Switch to non-root user
USER atc_api

# Set Django environment variable
ENV DJANGO_SETTINGS_MODULE=pe_reports_django.settings

# Run the application
CMD uvicorn --workers 4 pe_reports_django.asgi:app1 --host 0.0.0.0 --port 8000 --reload

