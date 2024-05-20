from google.cloud import bigquery
from google.cloud import kms
from Crypto.Cipher import AES
from Crypto.Util import Padding
import base64
import json
import asyncio

# Initialize clients
bq_client = bigquery.Client()
kms_client = kms.KeyManagementServiceClient()

# Decrypt symmetrically
def symmetric_decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = Padding.unpad(cipher.decrypt(base64.b64decode(ciphertext)), AES.block_size)
    return decrypted.decode()

# Asynchronously decrypt using asymmetric key
async def decrypt_asymmetric(latest_key, ciphertext):
    ciphertext_buffer = base64.b64decode(ciphertext)
    response = kms_client.asymmetric_decrypt(name=latest_key, ciphertext=ciphertext_buffer)
    return response.plaintext.decode()

# Asynchronously fetch latest key version
async def fetch_latest_key_version(project_id, location_id, key_ring_id, key_id):
    parent = kms_client.crypto_key_path(project_id, location_id, key_ring_id, key_id)
    response = kms_client.list_crypto_key_versions(request={"parent": parent})
    latest_version = response[0]  # Assuming versions are ordered by creation time
    latest_key = latest_version.name
    return latest_key

# Asynchronously fetch rows from BigQuery
async def fetch_rows(project_id, dataset_id, table_id):
    table_ref = f"{project_id}.{dataset_id}.{table_id}"
    query = f"SELECT * FROM `{table_ref}`"
    query_job = bq_client.query(query)
    rows = await query_job.result()
    return rows

# Insert data into BigQuery table
async def insert_data_into_table(table_ref, data):
    table = bq_client.get_table(table_ref)
    errors = await bq_client.insert_rows_json(table, [data])
    if errors:
        raise Exception(f"Error inserting rows: {errors}")

# Main decryption function
async def main(config):
    rows = await fetch_rows(**config['fetch_rows'])
    latest_key = await fetch_latest_key_version(**config['fetch_latest_key_version'])
    new_table_ref = f"{config['project_id']}.{config['new_dataset_id']}.{config['new_table_id']}"

    for row in rows:
        decrypted_row = {}
        encrypted_key = row['encrypted_key']
        key_value = await decrypt_asymmetric(latest_key, encrypted_key)
        key_value = json.loads(key_value)
        symmetric_key = key_value["key"]
        iv = base64.b64decode(key_value["iv"])

        for key, value in row.items():
            if key in config['columns_to_decrypt']:
                decrypted_value = symmetric_decrypt(value, symmetric_key, iv)
                decrypted_row[key] = decrypted_value

        await insert_data_into_table(new_table_ref, decrypted_row)

# Configuration
config = {
    'project_id': "your_project_id",
    'fetch_rows': {
        'project_id': "your_project_id",
        'dataset_id': "your_dataset_id",
        'table_id': "your_table_id"
    },
    'fetch_latest_key_version': {
        'project_id': "your_key_project_id",
        'location_id': "your_key_location_id",
        'key_ring_id': "your_key_ring_id",
        'key_id': "your_key_id"
    },
    'new_dataset_id': "your_new_dataset_id",
    'new_table_id': "your_new_table_id",
    'columns_to_decrypt': ["column1", "column2", "column3"]
}

# Run the main function
async def async_main():
    await main(config)

# Ensure it runs in the main thread
if __name__ == "__main__":
    asyncio.run(async_main())
