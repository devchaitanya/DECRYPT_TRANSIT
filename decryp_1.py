from google.cloud import bigquery

client = bigquery.Client()

def decrypt_table_data(project_id, dataset_id, encrypted_table_id, decrypted_table_id, columns_to_decrypt):
    # SELECTING A KEY FOR THE DECRYPTION
    selected_keyset_query = f"""
    DECLARE selected_keyset BYTES;

    SET selected_keyset = (SELECT keyset FROM `{project_id}.{dataset_id}.my_keysets` WHERE id = "{encrypted_table_id}");
    """
    client.query(selected_keyset_query).result()

    # DECRYPTING THE DATA
    decrypt_query = f"""
    CREATE OR REPLACE TABLE `{project_id}.{dataset_id}.{decrypted_table_id}` AS
    SELECT
      id,
        {', '.join([f"DETERMINISTIC_DECRYPT(KEYS.KEYSET_CHAIN('gcp-kms://projects/{project_id}/locations/asia-northeast1/keyRings/my-test-keyring/cryptoKeys/my-test-key', selected_keyset), {col}, '') AS {col}" for col in columns_to_decrypt])}
    FROM `{project_id}.{dataset_id}.{encrypted_table_id}`;
    """
    
    client.query(decrypt_query).result()

# TEST
project_id = "your-project-id"
dataset_id = "your-dataset-id"
encrypted_table_id = "your-encrypted-table-id"
decrypted_table_id = "your-decrypted-table-id"
columns_to_decrypt = ["column1", "column2", "column3"]

decrypt_table_data(project_id, dataset_id, encrypted_table_id, decrypted_table_id, columns_to_decrypt)
