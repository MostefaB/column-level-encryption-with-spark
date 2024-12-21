import sys
from awsglue.transforms import *
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job
import boto3
import base64 as b64
import logging
from botocore.exceptions import ClientError
from pyspark.sql.functions import *

# Initialize Glue and Spark Contexts
sc = SparkContext.getOrCreate()
glueContext = GlueContext(sc)
spark = glueContext.spark_session
job = Job(glueContext)

# Logger setup
logger = logging.getLogger(__name__)

# ColEncrypt class setup
class KeyManager:
    """Manages KMS data encryption keys."""

    def __init__(self, kms_client):
        self.kms_client = kms_client

    def generate_data_key(self, key_id: str) -> bytes:
        """Generates an encrypted data key."""
        try:
            data_key = self.kms_client.generate_data_key(KeyId=key_id, KeySpec="AES_256")
            return data_key["CiphertextBlob"]
        except ClientError as err:
            logger.error(f"Failed to generate data key: {err}")
            raise

    def decrypt_data_key(self, encrypted_key: bytes) -> bytes:
        """Decrypts an encrypted data key."""
        try:
            data_key = self.kms_client.decrypt(CiphertextBlob=encrypted_key)
            return data_key["Plaintext"]
        except ClientError as err:
            logger.error(f"Failed to decrypt data key: {err}")
            raise

class ColEncrypt:
    """Handles column-level encryption and decryption."""

    def __init__(self, data_frame, columns, key_id, kms_client, role_arn=None):
        if not data_frame or not columns or not key_id:
            raise ValueError("Invalid parameters provided.")

        self.df = data_frame
        self.columns = columns
        self.key_id = key_id
        self.kms_client = kms_client if role_arn is None else self._get_kms_client(role_arn)

    def _get_kms_client(self, role_arn):
        """Returns a KMS client assuming the provided IAM role."""
        sts_client = boto3.client("sts")
        creds = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="glue_job_session")["Credentials"]
        return boto3.client(
            "kms",
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )

    def encrypt(self):
        """Encrypts specified columns."""
        key_manager = KeyManager(self.kms_client)
        for column in self.columns:
            dek = key_manager.generate_data_key(self.key_id)
            decrypted_dek = key_manager.decrypt_data_key(dek)
            dek_b64 = b64.b64encode(dek).decode("utf-8")

            self.df = self.df.withColumn(
                "key", lit(decrypted_dek)
            ).withColumn(
                column,
                concat(lit(dek_b64 + "::"), base64(expr(f"aes_encrypt({column}, key)")))
            ).drop("key")
        return self.df

    def decrypt(self):
        """Decrypts specified columns."""
        key_manager = KeyManager(self.kms_client)
        for column in self.columns:
            first_row = self.df.select(column).first()
            if not first_row:
                raise ValueError(f"Column {column} is empty.")

            dek_b64, _ = first_row[column].split("::", 1)
            encrypted_dek = b64.b64decode(dek_b64)
            decrypted_dek = key_manager.decrypt_data_key(encrypted_dek)
            decrypted_dek_b64 = b64.b64encode(decrypted_dek).decode("utf-8")

            self.df = self.df.withColumn(
                column,
                expr(f"aes_decrypt(unbase64(split({column}, '::')[1]), unbase64('{decrypted_dek_b64}'))").cast("string")
            )
        return self.df

# S3 Paths
original_file = "s3://reb7v445miifapfm-glue-spark-test/sample-pci-data.csv"
encrypted_file = "s3://reb7v445miifapfm-glue-spark-test/sample-pci-data.csv_encrypted.csv"
decrypted_file = "s3://reb7v445miifapfm-glue-spark-test/sample-pci-data.csv_decrypted.csv"

# KMS and columns
kms_client = boto3.client("kms", region_name="us-east-2")
columns_to_encrypt = ["ssn", "Credit_Card_Number"]

# Load original file
df = glueContext.create_dynamic_frame.from_options(
    connection_type="s3",
    connection_options={"paths": [original_file]},
    format="csv",
    format_options={"withHeader": True}
).toDF()

# Encrypt columns
encryptor = ColEncrypt(df, columns_to_encrypt, "alias/spark", kms_client)
encrypted_df = encryptor.encrypt()
encrypted_df.write.csv(encrypted_file, mode="overwrite", header=True)

# Load encrypted file
encrypted_df = glueContext.create_dynamic_frame.from_options(
    connection_type="s3",
    connection_options={"paths": [encrypted_file]},
    format="csv",
    format_options={"withHeader": True}
).toDF()

# Decrypt columns
decryptor = ColEncrypt(encrypted_df, columns_to_encrypt, "alias/spark", kms_client)
decrypted_df = decryptor.decrypt()
decrypted_df.write.csv(decrypted_file, mode="overwrite", header=True)

# Validate files
original_df = df
decrypted_df = glueContext.create_dynamic_frame.from_options(
    connection_type="s3",
    connection_options={"paths": [decrypted_file]},
    format="csv",
    format_options={"withHeader": True}
).toDF()

if original_df.subtract(decrypted_df).isEmpty() and decrypted_df.subtract(original_df).isEmpty():
    print("Original and decrypted files are identical!")
else:
    print("Original and decrypted files differ!")

job.commit()
