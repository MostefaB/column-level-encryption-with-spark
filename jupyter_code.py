import base64 as b64

from pyspark.sql import SparkSession
from pyspark.sql.types import *
from pyspark.sql.functions import lit
from pyspark.sql.functions import *

spark = SparkSession.builder.appName("MyApp").getOrCreate()

df = spark.read.option("header", True).csv("sample-pci-data.csv")

encryption_key = "tEZPizBEj5EG5IDY1SvAECa5yZa5fVP1SrJGsGimx9I="
decoded_key = b64.b64decode(encryption_key)
# decoded_key = b"\xc27~\x15\xc7\x9a\x8a|\xb48\\\xd7\x894g-v\xac\xb5\n%\x17\x96g\xab\x88\x8a;|bU/"

# Encryption
df_encrypted = df.withColumn('SSN_Encrypted', base64(expr(f"aes_encrypt(SSN, unhex('{decoded_key.hex()}'), 'GCM')")))\
                 .withColumn('CreditCardNumber_Encrypted', base64(expr(f"aes_encrypt({df.columns[2]}, unhex('{decoded_key.hex()}'), 'GCM')")))
df_encrypted.show(truncate=False)

output_path = "./encrypted/sample-pci-data-encrypted.csv"
df_encrypted.write.csv(path=output_path, mode="overwrite", header=True, sep=",")

# Decryption
df = spark.read.option("header", True).csv("encrypted/sample-pci-data-encrypted.csv")
df.show()
df_decrypted = df.withColumn('SSN_Decrypted', expr(f"aes_decrypt(unbase64(SSN_Encrypted), unhex('{decoded_key.hex()}'), 'GCM')").cast("STRING"))\
                 .withColumn('CC_Decrypted', expr(f"aes_decrypt(unbase64(CreditCardNumber_Encrypted), unhex('{decoded_key.hex()}'), 'GCM')").cast("STRING"))
df_decrypted.show()