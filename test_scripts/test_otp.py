from pathlib import Path

ROOT = Path(__file__).parent.parent

import sys
sys.path.append(str(ROOT/"src"))

from mlcbase import *


def run():
    logger = Logger()
    logger.init_logger()

    ## TOTP
    logger.info("Generating TOTP secret...")
    totp_secret = generate_otp_secret(account_name="Test Account Name", 
                                      method="TOTP",
                                      return_qr_code=False,
                                      logger=logger)
    logger.info("Generating TOTP verification code...")
    totp_code = generate_otp_code(secret_key=totp_secret.secret, 
                                  method="TOTP",
                                  algorithm=totp_secret.metadata.algorithm,
                                  period=totp_secret.metadata.period,
                                  digits=totp_secret.metadata.digits,
                                  logger=logger)
    logger.info("Verifying TOTP code...")
    status = verify_otp_code(totp_code,
                             secret_key=totp_secret.secret,
                             method="TOTP",
                             algorithm=totp_secret.metadata.algorithm,
                             period=totp_secret.metadata.period,
                             digits=totp_secret.metadata.digits,
                             logger=logger)
    if not status:
        raise RuntimeError("TOTP code verification failed!")
    
    ## HOTP
    logger.info("Generating HOTP secret (initial_count=113)...")
    hotp_secret = generate_otp_secret(account_name="Test Account Name", 
                                      method="HOTP", 
                                      initial_count=113, 
                                      return_qr_code=False,
                                      logger=logger)
    logger.info("Generating HOTP verification code (code=150)...")
    hotp_code = generate_otp_code(secret_key=hotp_secret.secret, 
                                  count=150,
                                  method="HOTP",
                                  algorithm=hotp_secret.metadata.algorithm,
                                  initial_count=hotp_secret.metadata.initial_count,
                                  digits=hotp_secret.metadata.digits,
                                  logger=logger)
    status = verify_otp_code(hotp_code,
                             secret_key=hotp_secret.secret,
                             count=150,
                             method="HOTP",
                             algorithm=hotp_secret.metadata.algorithm,
                             initial_count=hotp_secret.metadata.initial_count,
                             digits=hotp_secret.metadata.digits,
                             logger=logger)
    if not status:
        raise RuntimeError("HOTP code verification failed!")
    
    logger.success("All tests passed!")


if __name__ == '__main__':
    run()
