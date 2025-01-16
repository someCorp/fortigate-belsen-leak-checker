#!/usr/bin/env python3
import os
import sys
import requests
import socket
import geoip2.database
from ipwhois import IPWhois
from concurrent.futures import ThreadPoolExecutor
import time
import random
import argparse

def checkModules():
  try:
    import geoip2.database
  except ImportError:
    errMsg = "\nfailed lib, try pip install geoip2\n"
    sys.stderr.write(errMsg)
    sys.exit(1)

  try:
    import ipwhois
  except ImportError:
    errMsg = "\nfailed lib, try pip install ipwhois\n"
    sys.stderr.write(errMsg)
    sys.exit(1)

  try:
    import requests
  except ImportError:
    errMsg = "\nfailed lib, try pip install requests\n"
    sys.stderr.write(errMsg)
    sys.exit(1)

homeDir = os.path.expanduser("~/fortigate-belsen-leak-checker")  # Application home directory
localIpFile = "affected_ips.txt"  # Path to the local file with IPs
geoipDb = "GeoLite2-City.mmdb"  # Path to the local GeoIP database
threads = 10
countryCodes = ("ag", "ar", "bb", "bz", "bo", "br", "ca", "cl", "co", "cr", "dm",
                "do", "ec", "sv", "gd", "gt", "gy", "ht", "hn", "jm", "mx", "ni",
                "pa", "py", "pe", "kn", "lc", "vc", "sr", "bs", "tt", "us", "uy",
                "ve")


def setupHomeDirectory(homeDir):
  try:
    os.makedirs(homeDir, exist_ok=True)
    os.chdir(homeDir)
    print(f"Directorio de trabajo configurado en: {os.getcwd()}")
  except Exception as e:
    print(f"Error configurando el directorio de trabajo: {e}")
    raise

def readLocalFile(filePath):
  try:
    with open(filePath, "r") as file:
      return [line.split(":")[0].strip() for line in file if line.strip()]
  except Exception as e:
    print(f"Error leyendo el archivo local: {e}")
    return []

def isIpFromCountry(ip, isoCode):
  try:
    with geoip2.database.Reader(geoipDb) as reader:
      response = reader.city(ip)
      return response.country.iso_code == isoCode
  except Exception as e:
    print(f"Error verificando GeoIP para {ip}: {e}")
    return False

def queryWhois(ip):
  time.sleep(random.uniform(0.5, 2.0))
  try:
    obj = IPWhois(ip)
    result = obj.lookup_rdap(asn_methods=["whois"])
    asn = result.get("asn", "Desconocido")
    contact = result.get("asn_cidr", "Desconocido")
    return asn, contact
  except Exception as e:
    print(f"Error en consulta WHOIS para {ip}: {e}")
    return "Desconocido", "Desconocido"

def getReverseDns(ip):
  try:
    return socket.gethostbyaddr(ip)[0]
  except socket.herror:
    return "No disponible"

def processIp(ip, isoCode):
  if not isIpFromCountry(ip, isoCode):
    return

  asn, contact = queryWhois(ip)
  reverseDns = getReverseDns(ip)

  print(f"{ip}\t{asn}\t{contact}\t{reverseDns}")

def main():
  checkModules()
  parser = argparse.ArgumentParser(description="Procesa una lista de IPs y obtiene información WHOIS y GeoIP.")
  parser.add_argument("--tld", required=True, choices=countryCodes,help="TLD del país en formato ISO (ejemplo: cl, ar, br)")
  args = parser.parse_args()
  isoCode = args.tld.upper()
  setupHomeDirectory(homeDir)
  print("Leyendo archivo local de IPs...")
  ipList = readLocalFile(localIpFile)
  if not ipList:
    print("No se pudieron obtener IPs para procesar.")
    return
  print("Procesando IPs...")
  startTime = time.time()
  with ThreadPoolExecutor(max_workers=threads) as executor:
    executor.map(lambda ip: processIp(ip, isoCode), ipList)
  elapsedTime = time.time() - startTime
  print(f"Procesamiento completo en {elapsedTime:.2f} segundos.")

if __name__ == "__main__":
  main()
