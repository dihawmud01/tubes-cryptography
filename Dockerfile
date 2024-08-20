# Gunakan image dasar Python
FROM python:3.9-slim

# Setel variabel lingkungan untuk memastikan Python tidak membuat file cache .pyc
ENV PYTHONUNBUFFERED True

# Tentukan direktori kerja di dalam container
WORKDIR /app

# Salin file requirements.txt ke direktori kerja
COPY requirements.txt .

# Instal dependensi Python
RUN pip install -r requirements.txt

# Salin semua kode ke direktori kerja
COPY . .

# Ekspose port yang digunakan oleh aplikasi Flask
EXPOSE 8080

# Setel command default untuk menjalankan aplikasi
CMD ["python", "app.py"]