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
    parser.add_argument("--python_version", required=True)

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
                        <span style="font-weight: bold;">Email:</span> <a href="mailto:mulingcloud@yeah.net">mulingcloud@yeah.net</a>, 
                        <a href="mailto:mulingcloud@163.com">mulingcloud@163.com</a>
                </div>
                <div style="font-family: Microsoft YaHei; font-size: 14px; margin-bottom: 20px;">
                        <span style="font-weight: bold;">Office Time:</span> Asia/Shanghai, 9:00-18:00, Mon.-Fri.
                </div>
                <a href="https://www.mulingcloud.com" style="text-decoration: none;">
                        <img src="https://lychee.weimingchen.net:1130/uploads/original/ab/f5/9b1e4627612dbd70aa62a1ae5370.png" height="50px">
                </a>"""
    attachment_path = str(Path(__file__).parent.parent / "tutorial" / "examples" / "YOLOv9.pdf")

    logger.info("Test SMTP with SSL")
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
        subject=f"Test Email from {platform.system()} using Python {args.python_version} (with SSL)",
        content="""<div style="font-family: Microsoft YaHei; font-size: 14px;">
                        This is a hello email sending through <span style="font-weight: bold;">mlcbase</span>.
                   </div>""",
        attachment=attachment_path,
        signature=signature
    )
    smtp_api.close()

    logger.info("Test SMTP without SSL")
    smtp_api = SMTPAPI(host=args.host, 
                       port=int(args.port_wo_ssl), 
                       name=args.name, 
                       address=args.address, 
                       password=args.password,
                       use_ssl=False,
                       logger=logger)
    smtp_api.send_email(
        receiver_name=args.receiver_name,
        receiver_email=args.receiver_email,
        subject=f"Test Email from {platform.system()} using Python {args.python_version} (without SSL)",
        content="""<div style="font-family: Microsoft YaHei; font-size: 14px;">
                        This is a hello email sending through <span style="font-weight: bold;">mlcbase</span>.
                   </div>""",
        attachment=attachment_path,
        signature=signature
    )
    smtp_api.close()


if __name__ == "__main__":
    run()
