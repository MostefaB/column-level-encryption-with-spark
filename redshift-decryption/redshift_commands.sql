-- Create TABLE
CREATE TABLE public.encrypted_data (
    first_last_name character varying(256) ENCODE lzo,
    ssn character varying(65535) ENCODE lzo,
    credit_card_number character varying(65535) ENCODE lzo
) DISTSTYLE AUTO;

-- Load data
COPY dev.public.encrypted_data (first_last_name, ssn, credit_card_number) 
FROM 's3://reb7v445miifapfm-glue-spark-test/sample-pci-data.csv_encrypted.csv' 
IAM_ROLE 'arn:aws:iam::111122223333:role/service-role/AmazonRedshift-CommandsAccessRole-20241223T103856' 
FORMAT AS CSV DELIMITER ',' 
QUOTE '"' 
IGNOREHEADER 1 
REGION AS 'us-east-2'

-- Query table
SELECT
    *
FROM
    "dev"."public"."encrypted_data";

-- Create UDF
CREATE OR REPLACE EXTERNAL FUNCTION decrypt_column(encrypted_value TEXT)
RETURNS TEXT
STABLE
IAM_ROLE 'arn:aws:iam::111122223333:role/service-role/AmazonRedshift-CommandsAccessRole-20241223T103856' 
LAMBDA 'arn:aws:lambda:us-east-2:111122223333:function:redshift-decrypt';

-- Query encrypted columns
SELECT
    first_last_name,
    decrypt_column(ssn) AS decrypted_ssn,
    decrypt_column(credit_card_number) AS decrypted_credit_card_number
FROM "dev"."public"."encrypted_data";
