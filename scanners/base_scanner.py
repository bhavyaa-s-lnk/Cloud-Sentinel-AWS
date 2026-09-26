import abc
import logging
from typing import List, Optional
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

from models.finding import Finding

logger = logging.getLogger("CloudSentinel")


class BaseScanner(abc.ABC):
    """Abstract base class for all CloudSentinel AWS service scanners."""

    def __init__(self, profile_name: str = "default", region_name: str = "us-east-1", demo_mode: bool = False):
        self.profile_name = profile_name
        self.region_name = region_name
        self.demo_mode = demo_mode
        self.retry_config = Config(
            retries={"max_attempts": 5, "mode": "standard"},
            connect_timeout=5,
            read_timeout=10
        )
        self.session: Optional[boto3.Session] = None

    def get_session(self) -> Optional[boto3.Session]:
        if self.demo_mode:
            return None
        if self.session is None:
            try:
                self.session = boto3.Session(profile_name=self.profile_name, region_name=self.region_name)
            except ProfileNotFound:
                logger.warning(f"AWS Profile '{self.profile_name}' not found. Falling back to default session credentials.")
                try:
                    self.session = boto3.Session(region_name=self.region_name)
                except Exception as e:
                    logger.error(f"Failed to create AWS session: {e}")
                    self.session = None
            except Exception as e:
                logger.error(f"Error creating session for profile '{self.profile_name}': {e}")
                self.session = None
        return self.session

    def get_client(self, service_name: str):
        """Creates a boto3 client with standard retry configuration."""
        if self.demo_mode:
            return None
        session = self.get_session()
        if not session:
            return None
        try:
            return session.client(service_name, config=self.retry_config)
        except Exception as e:
            logger.error(f"Failed to create client for {service_name}: {e}")
            return None

    def scan(self) -> List[Finding]:
        """Runs the scan and returns findings, handling authentication and exceptions gracefully."""
        if self.demo_mode:
            logger.info(f"Running {self.__class__.__name__} in DEMO/MOCK mode.")
            return self.run_demo_scan()

        try:
            findings = self.run_scan()
            return findings
        except (NoCredentialsError, ProfileNotFound) as e:
            logger.warning(f"No AWS credentials found ({e}). Falling back to demo findings for evaluation.")
            return self.run_demo_scan()
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_message = e.response.get("Error", {}).get("Message", str(e))
            logger.error(f"AWS ClientError [{error_code}] in {self.__class__.__name__}: {error_message}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error executing {self.__class__.__name__}: {e}", exc_info=True)
            return []

    @abc.abstractmethod
    def run_scan(self) -> List[Finding]:
        """Execute real AWS API security checks."""
        pass

    @abc.abstractmethod
    def run_demo_scan(self) -> List[Finding]:
        """Execute mock security checks with realistic AWS misconfigurations for evaluation."""
        pass
