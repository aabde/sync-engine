import os
import time
from hashlib import sha256

from inbox.config import config
from inbox.util.stats import statsd_client
from nylas.logging import get_logger
log = get_logger()

# TODO: store AWS credentials in a better way.
STORE_MSG_ON_S3 = config.get('STORE_MESSAGES_ON_S3', None)

if STORE_MSG_ON_S3:
    from boto.s3.connection import S3Connection
    from boto.s3.key import Key
    from boto.s3 import connect_to_region
else:
    from inbox.util.file import mkdirp

    def _data_file_directory(h):
        return os.path.join(config.get_required('MSG_PARTS_DIRECTORY'),
                            h[0], h[1], h[2], h[3], h[4], h[5])

    def _data_file_path(h):
        return os.path.join(_data_file_directory(h), h)


def save_to_blockstore(data_sha256, data):
    assert data is not None
    assert type(data) is not unicode

    if len(data) == 0:
        log.warning('Not saving 0-length data blob')
        return

    if STORE_MSG_ON_S3:
        _save_to_s3(data_sha256, data)
    else:
        directory = _data_file_directory(data_sha256)
        mkdirp(directory)

        with open(_data_file_path(data_sha256), 'wb') as f:
            f.write(data)


def is_in_blockstore(data_sha256):
    if STORE_MSG_ON_S3:
        return _is_in_s3(data_sha256)
    else:
        return os.path.exists(_data_file_path(data_sha256))


def get_from_blockstore(data_sha256):
    if STORE_MSG_ON_S3:
        value = _get_from_s3(data_sha256)
    else:
        value = _get_from_disk(data_sha256)

    if value is None:
        # We don't store None values so if such is returned, it's an error.
        log.error('No data returned!')
        return value

    assert data_sha256 == sha256(value).hexdigest(), \
        "Returned data doesn't match stored hash!"
    return value

def _get_connection:
    assert 'AWS_ACCESS_KEY_ID' in config, 'Need AWS key!'
    assert 'AWS_SECRET_ACCESS_KEY' in config, 'Need AWS secret!'
    assert 'MESSAGE_STORE_BUCKET_NAME' in config, \
        'Need bucket name to store message data!'
    region = config.get('AWS_REGION')
    AWS_ACCESS_KEY_ID = config.get('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = config.get('AWS_SECRET_ACCESS_KEY')

    if region:
        conn = connect_to_region('eu-west-1',
           aws_access_key_id=AWS_ACCESS_KEY_ID,
           aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
           is_secure=True,               # uncomment if you are not using ssl
           calling_format = boto.s3.connection.OrdinaryCallingFormat(),
           )
    else:
        conn = S3Connection(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)


def _save_to_s3(data_sha256, data):
    start = time.time()

    # Boto pools connections at the class level
    conn = _get_connection()
    bucket = conn.get_bucket(config.get('MESSAGE_STORE_BUCKET_NAME'),
                             validate=False)

    # See if it already exists; if so, don't recreate.
    key = bucket.get_key(data_sha256)
    if key:
        return

    key = Key(bucket)
    key.key = data_sha256
    key.set_contents_from_string(data)

    end = time.time()
    latency_millis = (end - start) * 1000
    statsd_client.timing('s3.save_latency', latency_millis)


def _is_in_s3(data_sha256):
    conn = _get_connection()
    bucket = conn.get_bucket(config.get('MESSAGE_STORE_BUCKET_NAME'),
                             validate=False)

    return bool(bucket.get_key(data_sha256))


def _get_from_s3(data_sha256):
    if not data_sha256:
        return None

    conn = _get_connection()
    bucket = conn.get_bucket(config.get('MESSAGE_STORE_BUCKET_NAME'),
                             validate=False)

    key = bucket.get_key(data_sha256)

    if not key:
        log.error('No key with name: {} returned!'.format(data_sha256))
        return

    return key.get_contents_as_string()


def _get_from_disk(data_sha256):
    if not data_sha256:
        return None

    try:
        with open(_data_file_path(data_sha256), 'rb') as f:
            return f.read()
    except IOError:
        log.error('No file with name: {}!'.format(data_sha256))
        return
