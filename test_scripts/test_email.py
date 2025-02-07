import argparse
import platform
from pathlib import Path

ROOT = Path(__file__).parent.parent

import sys
sys.path.append(str(ROOT/"src"))

from mlcbase import Logger, SMTPAPI


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True)
    parser.add_argument("--port_wo_ssl", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--address", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--receiver_name", required=True)
    parser.add_argument("--receiver_email", required=True)
    parser.add_argument("--job_status", required=True)
    parser.add_argument("--python_version", nargs="+")

    args = parser.parse_args()
    return args


def run():
    args = parse_args()

    logger = Logger()
    logger.init_logger()

    signature = """<div style="font-family: Microsoft YaHei; font-size: 14px;">Thanks for using MuLingCloud</div>
                <div style="margin-top: 10px;margin-bottom: 10px;">----</div>
                <div style="margin-bottom: 10px;">
                        <a href="https://github.com/wmchen/mlcbase"><img src="https://img.shields.io/badge/github_repository-888888?logo=github&logoColor=black" /></a>
                        <a href="https://gitlab.com/wm-chen/mlcbase"><img src="https://img.shields.io/badge/gitlab_repository-888888?logo=gitlab" /></a>
                        <a href="https://gitee.com/wm-chen/mlcbase"><img src="https://img.shields.io/badge/gitee_repository-888888?logo=gitee&logoColor=C71D23" /></a>
                </div>
                <div style="font-family: Microsoft YaHei; font-size: 16px; font-weight: bold;margin-bottom: 10px">MuLingCloud</div>
                <div style="font-family: Microsoft YaHei; font-size: 14px; margin-bottom: 5px;">
                        <span style="font-weight: bold;">Email:</span> <a href="mailto:service@mulingcloud.com">service@mulingcloud.com</a>
                </div>
                <div style="font-family: Microsoft YaHei; font-size: 14px; margin-bottom: 20px;">
                        <span style="font-weight: bold;">Office Time:</span> Asia/Shanghai, 9:00-18:00, Mon.-Fri.
                </div>"""

    if isinstance(args.python_version, list):
        python_version = f"{args.python_version[0]}-{args.python_version[-1]}"
    else:
        python_version = args.python_version

    logger.info("SMTP with SSL")
    if args.job_status == "success":
        subject = "Job Success"
        content = f"Your validation job on {platform.system()} (Python {python_version}) has been successfully completed."
    else:
        subject = "Job Failed"
        content = f"Your validation job on {platform.system()} (Python {python_version}) has failed."
    smtp_api = SMTPAPI(host=args.host, 
                       port=int(args.port), 
                       name=args.name, 
                       address=args.address, 
                       password=args.password,
                       use_ssl=True,
                       logger=logger)
    smtp_api.send_email(
        receiver_name=args.receiver_name,
        receiver_email=args.receiver_email,
        subject=subject,
        content=content,
        signature=signature
    )
    smtp_api.close()


if __name__ == "__main__":
    run()
