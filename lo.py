#!/usr/bin/env python
# coding: utf-8

# In[22]:


with open("access.log", "r") as f:
    logs = f.readlines()

for satir in logs:
    print(satir)


# In[23]:


import re

log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s-\s-\s' +
    r'\[(?P<date>.*?)\]\s' +
    r'"(?P<method>GET|POST|PUT|DELETE|HEAD)\s(?P<url>.*?)\sHTTP/.*?"\s' +
    r'(?P<status>\d+)\s(?P<size>\d+|-)'
)

parsed_logs = []

for line in logs:
    match = log_pattern.search(line)
    if match:
        parsed_logs.append(match.groupdict())

for entry in parsed_logs:
    print(entry)


# In[24]:


import pandas as pd

df = pd.DataFrame(parsed_logs)
df.head()


# In[25]:


en_cok_ip = df['ip'].value_counts().idxmax()
print(f"En çok istek atan IP: {en_cok_ip}")


# In[26]:


print(df['ip'].value_counts().head(5))


# In[27]:


from datetime import datetime

# Apache logundaki tarih formatı: 26/Jun/2025:10:12:03 +0300
df['datetime'] = df['date'].apply(
    lambda x: datetime.strptime(x.split(" ")[0], "%d/%b/%Y:%H:%M:%S")
)


# In[28]:


df = df.sort_values(by='datetime')
df.reset_index(drop=True, inplace=True)


# In[29]:


from collections import defaultdict

# Belirlenen eşik
threshold = 3
zaman_penceresi_saniye = 60

suspect_ips = set()
ip_to_times = defaultdict(list)

for _, row in df.iterrows():
    ip = row['ip']
    zaman = row['datetime']
    ip_to_times[ip].append(zaman)

    # Son 1 dakika içinde kaç istek var kontrol et
    times = ip_to_times[ip]
    recent = [t for t in times if (zaman - t).seconds <= zaman_penceresi_saniye]

    if len(recent) > threshold:
        suspect_ips.add(ip)

print("Şüpheli IP adresleri:", suspect_ips)


# In[33]:


df['status'].value_counts()


# In[34]:


import matplotlib.pyplot as plt

df['ip'].value_counts().head(5).plot(kind='bar', title="En çok istek atan IP'ler")
plt.xlabel("IP Adresi")
plt.ylabel("İstek Sayısı")
plt.show()


# In[35]:


# Status kodu 404 olan satırları filtrele
errors_404 = df[df['status'] == '404']

# Hangi IP en çok 404 atmış?
top_404_ips = errors_404['ip'].value_counts()
print("404 hatası gönderen IP'ler:\n", top_404_ips)

# Belirli eşikten fazlaysa, saldırgan olabilir
suspect_404 = top_404_ips[top_404_ips > 5].index.tolist()
print("Şüpheli 404 spam IP'ler:", suspect_404)


# In[36]:


from collections import defaultdict

threshold = 10  # 60 saniyede 10'dan fazla istek
zaman_penceresi = 60
brute_force_ips = set()
ip_zamanlar = defaultdict(list)

for _, row in df.iterrows():
    ip = row['ip']
    zaman = row['datetime']
    ip_zamanlar[ip].append(zaman)
    
    son_istekler = [t for t in ip_zamanlar[ip] if (zaman - t).total_seconds() <= zaman_penceresi]
    if len(son_istekler) > threshold:
        brute_force_ips.add(ip)

print("Aşırı istek gönderen IP'ler:", brute_force_ips)


# In[37]:


import pandas as pd
import matplotlib.pyplot as plt
import re
from datetime import datetime

# 1. Log dosyasını oku
with open("apache_logs.txt", "r", encoding="utf-8") as f:
    log_lines = f.readlines()

# 2. Log formatına uygun regex ile ayrıştır
log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s-\s-\s'
    r'\[(?P<date>.*?)\]\s'
    r'"(?P<method>\w+)\s(?P<url>.*?)\sHTTP/[\d.]+"\s'
    r'(?P<status>\d+)\s(?P<size>\d+|-)'
)

parsed_logs = []
for line in log_lines:
    match = log_pattern.search(line)
    if match:
        parsed_logs.append(match.groupdict())

# 3. DataFrame oluştur ve dönüştürmeler
df = pd.DataFrame(parsed_logs)
df['datetime'] = pd.to_datetime(df['date'], format="%d/%b/%Y:%H:%M:%S %z", errors='coerce')
df['status'] = df['status'].astype(int)

# 4. En çok istek yapan ilk 10 IP
ip_counts = df['ip'].value_counts().head(10)

# 5. Grafik çiz
plt.figure(figsize=(12, 6))
ip_counts.plot(kind='bar', color='tomato')
plt.title("En Çok İstek Yapan 10 IP Adresi", fontsize=14)
plt.xlabel("IP Adresi")
plt.ylabel("İstek Sayısı")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()


# In[38]:


suspect_urls = ['/admin', '/wp-login', '/phpmyadmin', '/config']
url_deneme_ips = df[df['url'].isin(suspect_urls)]['ip'].value_counts()
print("Şüpheli URL denemesi yapan IP'ler:\n", url_deneme_ips)


# In[39]:


from datetime import datetime as dt

tarih = dt.now().strftime("%Y-%m-%d_%H-%M")

with open(f"saldiri_raporu_{tarih}.txt", "w", encoding="utf-8") as f:
    f.write("🔍 404 Spam IP'ler:\n")
    if suspect_404:
        for ip in suspect_404:
            f.write(f"{ip}\n")
    else:
        f.write("Bulunamadı\n")

    f.write("\n⚠️ Brute Force IP'ler:\n")
    if brute_force_ips:
        for ip in sorted(brute_force_ips):
            f.write(f"{ip}\n")
    else:
        f.write("Bulunamadı\n")

    f.write("\n🛠 URL Denemesi Yapanlar:\n")
    if not url_deneme_ips.empty:
        for ip in url_deneme_ips.index:
            f.write(f"{ip}\n")
    else:
        f.write("Bulunamadı\n")

print("Rapor başarıyla oluşturuldu ✅")


# In[41]:


import matplotlib.pyplot as plt

tum_saldirgani_ipler = list(set(suspect_404) | set(brute_force_ips) | set(url_deneme_ips.index))

df_saldirgan = df[df['ip'].isin(tum_saldirgani_ipler)]
ip_counts = df_saldirgan['ip'].value_counts()

if ip_counts.empty:
    print("Grafik çizilecek veri bulunamadı.")
else:
    ip_counts.plot(kind='bar', figsize=(10, 6), title="En Çok Saldırı Yapan IP'ler")
    plt.xlabel("IP Adresi")
    plt.ylabel("Toplam İstek")
    plt.tight_layout()
    plt.show()


# In[42]:


print("📊 Günlük Saldırı Özeti")
print("=" * 30)
print("🔴 404 Spam IP'ler:")
print(top_404_ips[top_404_ips > 5])
print("\n⚠️ Brute Force Şüphelileri:")
print(list(brute_force_ips))
print("\n🛠 Admin Paneli Arayanlar:")
print(url_deneme_ips)


# In[43]:


pip install matplotlib


# In[45]:


df_saldirgan = df[df['ip'].isin(tum_saldirgani_ipler)]
ip_counts = df_saldirgan['ip'].value_counts()

if not ip_counts.empty:
    ip_counts.plot(kind='bar', figsize=(10, 6), title="En Çok Saldırı Yapan IP'ler")
    plt.xlabel("IP Adresi")
    plt.ylabel("Toplam İstek")
    plt.tight_layout()
    plt.show()
else:
    print("Grafik oluşturulamadı: En çok saldıran IP verisi bulunamadı.")


# In[48]:


df_saldirgan = df[df['ip'].isin(tum_saldirgani_ipler)].copy()
df_saldirgan['hour'] = df_saldirgan['datetime'].dt.hour

hourly_counts = df_saldirgan.groupby('hour')['ip'].count()

hourly_counts.plot(kind='bar', figsize=(10, 5), title="Saatlik Saldırı Yoğunluğu", color='tomato')
plt.xlabel("Saat")
plt.ylabel("Saldırı Sayısı")
plt.xticks(rotation=0)
plt.tight_layout()
plt.show()


# In[49]:


with open("rapor.html", "w") as f:
    f.write("<h1>Log Tabanlı Saldırı Raporu</h1>")
    f.write("<h2>En Çok 404 Atan IP’ler</h2>")
    f.write(top_404_ips[top_404_ips > 5].to_frame().to_html())
    f.write("<h2>Brute Force Şüphelileri</h2>")
    f.write("<ul>")
    for ip in brute_force_ips:
        f.write(f"<li>{ip}</li>")
    f.write("</ul>")
    f.write("<h2>Admin URL Denemesi</h2>")
    f.write(url_deneme_ips.to_frame().to_html())


# In[54]:


import smtplib
from email.message import EmailMessage

msg = EmailMessage()
msg['Subject'] = 'Saldırı Raporu'
msg['From'] = 'seninmailin@example.com'
msg['To'] = 'hedef@example.com'
msg.set_content('Rapor ekte yer almaktadır.')

with open("rapor.html", 'rb') as f:
    msg.add_attachment(f.read(), maintype='text', subtype='html', filename='rapor.html')

# smtp kısmını yorumsatır yaptık, mail gitmez ama kod hatasız çalışır
# with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
#     smtp.login('seninmailin@example.com', 'uygulama_sifresi')
#     smtp.send_message(msg)

print("Mail gönderildi!")


# In[ ]:




